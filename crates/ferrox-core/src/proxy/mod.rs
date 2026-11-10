//! Proxy HTTP/HTTPS : mode explicite (HTTP + CONNECT), transparent HTTP,
//! transparent HTTPS (routage par SNI), et interception TLS optionnelle.

pub mod body;
pub mod sni;

use crate::access::{client_allowed, connect_port_allowed, BasicAuth, BypassCache, Cidr};
use crate::event::{now_ms, Action, Event, EventSink, HttpEvent, Scheme};
use crate::filter::{normalize_host, BlockReason, Filter};
use crate::http_client::{HttpsClient, ProxyBody};
use crate::tls::CertAuthority;
use body::{Counted, EventGuard, Prepend};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// Octets de réponse inspectés pour reconnaître un type de fichier (ISO : 0x8001 + 5).
const SNIFF_LEN: usize = 36 * 1024;
/// Attente maximale pour réunir ces octets avant de relayer ce qui est arrivé.
const SNIFF_WAIT: Duration = Duration::from_secs(3);

pub struct ProxyCtx {
    pub filter: Arc<Filter>,
    pub sink: EventSink,
    pub client: HttpsClient,
    pub ca: Option<Arc<CertAuthority>>,
    pub bypass: Vec<String>,
    /// Hôtes dont la poignée de main interceptée échoue à répétition (épinglage) :
    /// tunnel direct pendant un temps limité.
    pub auto_bypass: BypassCache,
    /// Réseaux clients autorisés ; les autres sont refusés dès l'acceptation.
    pub allow: Vec<Cidr>,
    /// Ports acceptés pour CONNECT.
    pub connect_ports: Vec<u16>,
    /// Authentification Basic du proxy explicite.
    pub auth: Option<BasicAuth>,
    /// Plafond de connexions clientes simultanées.
    pub slots: Arc<Semaphore>,
    pub connect_timeout: Duration,
    /// Attente des en-têtes de réponse amont.
    pub response_timeout: Duration,
    /// Inactivité maximale d'un tunnel.
    pub idle_timeout: Duration,
    pub active: Arc<AtomicU64>,
}

impl ProxyCtx {
    fn should_mitm(&self, host: &str, port: u16) -> bool {
        self.ca.is_some()
            && matches!(port, 443 | 8443)
            && !self.auto_bypass.is_bypassed(host)
            && !self
                .bypass
                .iter()
                .any(|b| host == b || host.ends_with(&format!(".{b}")))
    }
}

#[derive(Clone)]
enum Mode {
    Explicit,
    TransparentHttp,
    Mitm { host: String, port: u16 },
}

struct ActiveGuard(Arc<AtomicU64>);
impl ActiveGuard {
    fn new(a: &Arc<AtomicU64>) -> Self {
        a.fetch_add(1, Ordering::Relaxed);
        Self(a.clone())
    }
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------- écouteurs

pub async fn run_explicit(listener: TcpListener, ctx: Arc<ProxyCtx>) {
    accept_loop(listener, ctx, |stream, peer, ctx| async move {
        serve_http(stream, peer.ip(), ctx, Mode::Explicit).await;
    })
    .await
}

pub async fn run_transparent_http(listener: TcpListener, ctx: Arc<ProxyCtx>) {
    accept_loop(listener, ctx, |stream, peer, ctx| async move {
        serve_http(stream, peer.ip(), ctx, Mode::TransparentHttp).await;
    })
    .await
}

pub async fn run_transparent_https(listener: TcpListener, ctx: Arc<ProxyCtx>) {
    accept_loop(listener, ctx, |stream, peer, ctx| async move {
        transparent_tls(stream, peer.ip(), ctx).await;
    })
    .await
}

async fn accept_loop<F, Fut>(listener: TcpListener, ctx: Arc<ProxyCtx>, f: F)
where
    F: Fn(TcpStream, SocketAddr, Arc<ProxyCtx>) -> Fut + Send + Sync + 'static + Clone,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                if !client_allowed(peer.ip(), &ctx.allow) {
                    tracing::debug!("{peer} : client hors des réseaux autorisés, refusé");
                    continue;
                }
                let Ok(permit) = ctx.slots.clone().try_acquire_owned() else {
                    tracing::warn!("{peer} : plafond de connexions atteint, refusé");
                    continue;
                };
                let _ = stream.set_nodelay(true);
                let ctx = ctx.clone();
                let f = f.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _g = ActiveGuard::new(&ctx.active);
                    f(stream, peer, ctx).await;
                });
            }
            Err(e) => {
                tracing::warn!("accept : {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn serve_http<S>(io: S, client: IpAddr, ctx: Arc<ProxyCtx>, mode: Mode)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc_ctx = ctx.clone();
    let svc = service_fn(move |req: Request<Incoming>| {
        let ctx = svc_ctx.clone();
        let mode = mode.clone();
        async move { Ok::<_, Infallible>(handle(req, client, ctx, mode).await) }
    });
    let conn = http1::Builder::new()
        .preserve_header_case(true)
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .serve_connection(TokioIo::new(io), svc)
        .with_upgrades();
    if let Err(e) = conn.await {
        tracing::debug!("connexion {client} : {e}");
    }
}

// ---------------------------------------------------------------- traitement HTTP

const HOP_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn strip_hop_headers(h: &mut HeaderMap) {
    // Les en-têtes cités dans Connection sont aussi propres au saut.
    let listed: Vec<HeaderName> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for n in listed {
        h.remove(n);
    }
    for n in HOP_HEADERS {
        h.remove(*n);
    }
}

fn header_str(h: &HeaderMap, name: header::HeaderName) -> Option<String> {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(512).collect())
}

fn full(body: impl Into<Bytes>) -> ProxyBody {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn block_page(host: &str, r: &BlockReason) -> Response<ProxyBody> {
    let page = format!(
        "<!doctype html><html lang=fr><meta charset=utf-8><title>Bloqué par Ferrox</title>\
<body style=\"margin:0;background:#101113;color:#e9e6e1;font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:100vh\">\
<main style=\"max-width:560px;padding:32px;border-left:4px solid #e0632e;background:#17191c\">\
<p style=\"letter-spacing:.2em;font-size:12px;color:#e0632e;margin:0\">FERROX</p>\
<h1 style=\"font-size:24px;margin:8px 0 16px\">Accès bloqué</h1>\
<p>La ressource <b>{}</b> a été bloquée par la politique de filtrage.</p>\
<p style=\"color:#9a958d\">Motif : {} &middot; catégorie : {}</p></main></body></html>",
        html_escape(host),
        html_escape(&r.reason),
        html_escape(&r.category)
    );
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(full(page))
        .unwrap()
}

fn auth_required() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(
            header::PROXY_AUTHENTICATE,
            "Basic realm=\"Ferrox\", charset=\"UTF-8\"",
        )
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full("Ferrox : authentification requise\n"))
        .unwrap()
}

fn simple(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(msg.to_string()))
        .unwrap()
}

fn split_authority(auth: &str, default_port: u16) -> (String, u16) {
    let host = normalize_host(auth);
    let port = auth
        .rsplit_once(':')
        .filter(|(h, _)| !h.ends_with(':') && (h.starts_with('[') || !h.contains(':')))
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(default_port);
    (host, port)
}

fn base_event(client: IpAddr, method: &str, scheme: Scheme, host: &str, port: u16) -> HttpEvent {
    HttpEvent {
        ts: now_ms(),
        client,
        method: method.to_string(),
        scheme,
        host: host.to_string(),
        port,
        path: None,
        status: 0,
        bytes_up: 0,
        bytes_down: 0,
        duration_ms: 0,
        user_agent: None,
        content_type: None,
        action: Action::Allow,
        reason: None,
        category: None,
    }
}

fn emit_now(
    ctx: &ProxyCtx,
    mut ev: HttpEvent,
    status: u16,
    block: Option<&BlockReason>,
    start: Instant,
) {
    ev.status = status;
    ev.duration_ms = start.elapsed().as_millis().min(u32::MAX as u128) as u32;
    if let Some(b) = block {
        ev.action = Action::Block;
        ev.reason = Some(b.reason.clone());
        ev.category = Some(b.category.clone());
    }
    ctx.sink.emit(Event::Http(ev));
}

async fn handle(
    req: Request<Incoming>,
    client: IpAddr,
    ctx: Arc<ProxyCtx>,
    mode: Mode,
) -> Response<ProxyBody> {
    // Authentification du proxy explicite (les requêtes interceptées l'ont déjà passée au CONNECT).
    if let (Mode::Explicit, Some(auth)) = (&mode, &ctx.auth) {
        let h = req.headers().get(header::PROXY_AUTHORIZATION);
        if !auth.check(h.map(HeaderValue::as_bytes)) {
            let mut ev = base_event(client, req.method().as_str(), Scheme::Http, "", 0);
            if let Some(a) = req.uri().authority() {
                let (h, p) = split_authority(a.as_str(), 80);
                ev.host = h;
                ev.port = p;
            }
            ev.reason = Some("authentification proxy refusée".into());
            ev.action = Action::Block;
            emit_now(&ctx, ev, 407, None, Instant::now());
            return auth_required();
        }
    }
    if req.method() == Method::CONNECT {
        return match mode {
            Mode::Explicit => connect(req, client, ctx).await,
            _ => simple(
                StatusCode::METHOD_NOT_ALLOWED,
                "CONNECT non pris en charge ici",
            ),
        };
    }
    let start = Instant::now();

    // Détermination de la cible.
    let path_q = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let (scheme, authority) =
        match &mode {
            Mode::Explicit => match (req.uri().scheme_str(), req.uri().authority()) {
                (Some(s), Some(a)) => (s.to_string(), a.as_str().to_string()),
                _ => return simple(
                    StatusCode::OK,
                    "Ferrox : proxy actif. Configurez ce point d'accès comme proxy HTTP/HTTPS.\n",
                ),
            },
            Mode::TransparentHttp => match header_str(req.headers(), header::HOST) {
                Some(h) => ("http".to_string(), h),
                None => return simple(StatusCode::BAD_REQUEST, "en-tête Host manquant"),
            },
            Mode::Mitm { host, port } => (
                "https".to_string(),
                if *port == 443 {
                    host.clone()
                } else {
                    format!("{host}:{port}")
                },
            ),
        };
    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host, port) = split_authority(&authority, default_port);
    let ev_scheme = if scheme == "https" {
        Scheme::Https
    } else {
        Scheme::Http
    };

    let mut ev = base_event(client, req.method().as_str(), ev_scheme, &host, port);
    ev.path = Some(path_q.chars().take(1024).collect());
    ev.user_agent = header_str(req.headers(), header::USER_AGENT);

    // Filtrage avant tout contact avec l'amont.
    let filter = ctx.filter.current();
    if let Some(r) = filter
        .check_domain(&host)
        .or_else(|| filter.check_path(&path_q))
    {
        emit_now(&ctx, ev, 403, Some(&r), start);
        return block_page(&host, &r);
    }

    // Taille approximative de la ligne de requête et des en-têtes.
    let header_up = (req.method().as_str().len() + path_q.len() + 12) as u64
        + req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().len() + v.len() + 4) as u64)
            .sum::<u64>();

    let (mut parts, body) = req.into_parts();
    strip_hop_headers(&mut parts.headers);
    let uri = format!("{scheme}://{authority}{path_q}");
    parts.uri = match uri.parse() {
        Ok(u) => u,
        Err(_) => return simple(StatusCode::BAD_REQUEST, "URL invalide"),
    };
    parts.version = hyper::Version::HTTP_11;
    if !parts.headers.contains_key(header::HOST) {
        if let Ok(v) = HeaderValue::from_str(&authority) {
            parts.headers.insert(header::HOST, v);
        }
    }

    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    let upstream_req = Request::from_parts(parts, Counted::new(body, up.clone(), None).boxed());

    let resp =
        match tokio::time::timeout(ctx.response_timeout, ctx.client.request(upstream_req)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                ev.reason = Some(format!("amont : {e}"));
                ev.bytes_up = header_up + up.load(Ordering::Relaxed);
                emit_now(&ctx, ev, 502, None, start);
                return simple(
                    StatusCode::BAD_GATEWAY,
                    "Ferrox : serveur amont injoignable",
                );
            }
            Err(_) => {
                ev.reason = Some("amont : délai dépassé".into());
                emit_now(&ctx, ev, 504, None, start);
                return simple(StatusCode::GATEWAY_TIMEOUT, "Ferrox : délai dépassé");
            }
        };

    let (mut rparts, rbody) = resp.into_parts();
    ev.status = rparts.status.as_u16();
    ev.content_type = header_str(&rparts.headers, header::CONTENT_TYPE);

    if let Some(ct) = &ev.content_type {
        if let Some(r) = filter.check_mime(ct) {
            emit_now(&ctx, ev, 403, Some(&r), start);
            return block_page(&host, &r);
        }
    }

    // Inspection de la signature du fichier sur les premiers Kio (décompressés si besoin).
    let mut rbody = rbody;
    let mut first = Vec::new();
    if filter.wants_sniff() && rparts.status.is_success() {
        match read_head(&mut rbody, &mut first).await {
            Ok(head) => {
                let enc = header_str(&rparts.headers, header::CONTENT_ENCODING);
                let decoded = decoded_head(enc.as_deref(), &head);
                let hit = decoded
                    .as_deref()
                    .and_then(|d| filter.check_magic(d))
                    .or_else(|| filter.check_magic(&head));
                if let Some(r) = hit {
                    emit_now(&ctx, ev, 403, Some(&r), start);
                    return block_page(&host, &r);
                }
            }
            Err(e) => {
                ev.reason = Some(format!("amont : {e}"));
                emit_now(&ctx, ev, 502, None, start);
                return simple(StatusCode::BAD_GATEWAY, "Ferrox : réponse amont invalide");
            }
        }
    }
    drop(filter);

    strip_hop_headers(&mut rparts.headers);
    let guard = EventGuard {
        ev: Some(ev),
        start,
        header_up,
        up,
        down: down.clone(),
        sink: ctx.sink.clone(),
    };
    let body = Counted::new(Prepend::new(first, rbody), down, Some(guard)).boxed();
    Response::from_parts(rparts, body)
}

/// Lit les premières trames de la réponse, jusqu'à `SNIFF_LEN` octets ou `SNIFF_WAIT`.
/// Les trames lues sont rendues dans `frames` pour être relayées telles quelles.
async fn read_head(
    body: &mut Incoming,
    frames: &mut Vec<Frame<Bytes>>,
) -> Result<Vec<u8>, hyper::Error> {
    let mut head = Vec::new();
    let deadline = tokio::time::Instant::now() + SNIFF_WAIT;
    while head.len() < SNIFF_LEN {
        match tokio::time::timeout_at(deadline, body.frame()).await {
            Err(_) | Ok(None) => break,
            Ok(Some(Err(e))) => return Err(e),
            Ok(Some(Ok(f))) => {
                let data = f.is_data();
                if let Some(d) = f.data_ref() {
                    let take = d.len().min(SNIFF_LEN - head.len());
                    head.extend_from_slice(&d[..take]);
                }
                frames.push(f);
                if !data {
                    break;
                }
            }
        }
    }
    Ok(head)
}

/// Décompresse le début d'un corps gzip ou deflate (lecture partielle acceptée).
fn decoded_head(encoding: Option<&str>, raw: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let enc = encoding?.trim().to_ascii_lowercase();
    let reader: Box<dyn Read + '_> = match enc.as_str() {
        "gzip" | "x-gzip" => Box::new(flate2::read::GzDecoder::new(raw)),
        "deflate" => Box::new(flate2::read::ZlibDecoder::new(raw)),
        _ => return None,
    };
    let mut out = Vec::with_capacity(SNIFF_LEN);
    // Un flux tronqué renvoie une erreur, mais les octets déjà décodés restent dans `out`.
    let _ = reader.take(SNIFF_LEN as u64).read_to_end(&mut out);
    (!out.is_empty()).then_some(out)
}

// ---------------------------------------------------------------- CONNECT

async fn connect(
    req: Request<Incoming>,
    client: IpAddr,
    ctx: Arc<ProxyCtx>,
) -> Response<ProxyBody> {
    let start = Instant::now();
    let Some(auth) = req.uri().authority().map(|a| a.as_str().to_string()) else {
        return simple(StatusCode::BAD_REQUEST, "CONNECT sans autorité");
    };
    let (host, port) = split_authority(&auth, 443);
    let mut ev = base_event(client, "CONNECT", Scheme::Tunnel, &host, port);
    ev.user_agent = header_str(req.headers(), header::USER_AGENT);

    if !connect_port_allowed(port, &ctx.connect_ports) {
        let r = BlockReason {
            reason: format!("port CONNECT {port} non autorisé"),
            category: "policy".into(),
        };
        emit_now(&ctx, ev, 403, Some(&r), start);
        return simple(
            StatusCode::FORBIDDEN,
            "Ferrox : port de destination non autorisé pour CONNECT",
        );
    }

    if let Some(r) = ctx.filter.load().check_domain(&host) {
        emit_now(&ctx, ev, 403, Some(&r), start);
        return block_page(&host, &r);
    }

    if ctx.should_mitm(&host, port) {
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(up) => mitm(TokioIo::new(up), client, host, port, ev, ctx).await,
                Err(e) => tracing::debug!("upgrade : {e}"),
            }
        });
        return Response::new(crate::http_client::empty());
    }

    // Connexion amont avant de répondre, pour renvoyer une vraie erreur 502.
    let upstream = match tokio::time::timeout(
        ctx.connect_timeout,
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            ev.reason = Some(format!("connexion : {e}"));
            emit_now(&ctx, ev, 502, None, start);
            return simple(StatusCode::BAD_GATEWAY, "Ferrox : connexion impossible");
        }
        Err(_) => {
            ev.reason = Some("connexion : délai dépassé".into());
            emit_now(&ctx, ev, 504, None, start);
            return simple(StatusCode::GATEWAY_TIMEOUT, "Ferrox : délai dépassé");
        }
    };
    let _ = upstream.set_nodelay(true);
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(up) => splice(TokioIo::new(up), upstream, ev, 200, start, &ctx).await,
            Err(e) => tracing::debug!("upgrade : {e}"),
        }
    });
    Response::new(crate::http_client::empty())
}

/// Relaie deux flux et émet l'événement de tunnel à la fermeture.
async fn splice<A>(
    a: A,
    b: TcpStream,
    mut ev: HttpEvent,
    status: u16,
    start: Instant,
    ctx: &ProxyCtx,
) where
    A: AsyncRead + AsyncWrite + Unpin,
{
    let (up, down) = splice_idle(a, b, ctx.idle_timeout).await;
    ev.bytes_up += up;
    ev.bytes_down += down;
    emit_now(ctx, ev, status, None, start);
}

/// Copie un sens du tunnel ; s'arrête après `idle` sans aucun octet reçu.
async fn pipe<R, W>(mut r: R, mut w: W, idle: Duration) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = match tokio::time::timeout(idle, r.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            // Fin de flux, erreur ou inactivité trop longue.
            _ => break,
        };
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        total += n as u64;
    }
    let _ = w.shutdown().await;
    total
}

/// Remplace `copy_bidirectional` avec un délai d'inactivité : renvoie (montant, descendant).
pub async fn splice_idle<A, B>(a: A, b: B, idle: Duration) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    tokio::join!(pipe(ar, bw, idle), pipe(br, aw, idle))
}

type BoxFut = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// Future boxée : rompt la récursion de types handle -> CONNECT -> mitm -> handle.
fn mitm<S>(
    io: S,
    client: IpAddr,
    host: String,
    port: u16,
    ev: HttpEvent,
    ctx: Arc<ProxyCtx>,
) -> BoxFut
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Box::pin(async move {
        let start = Instant::now();
        let ca = ctx.ca.clone().expect("CA présente");
        let acceptor = tokio_rustls::TlsAcceptor::from(ca.server_config(&host));
        match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(io)).await {
            Ok(Ok(tls)) => {
                let sni = tls
                    .get_ref()
                    .1
                    .server_name()
                    .map(normalize_host)
                    .unwrap_or(host);
                serve_http(tls, client, ctx, Mode::Mitm { host: sni, port }).await;
            }
            other => {
                // Certificat refusé (épinglage, CA non installée) : après plusieurs échecs,
                // tunnel direct pour un temps limité.
                let msg = match other {
                    Ok(Err(e)) => format!("interception refusée : {e}"),
                    _ => "interception : délai dépassé".into(),
                };
                ctx.auto_bypass.record_failure(&host);
                let mut ev = ev;
                ev.reason = Some(msg);
                emit_now(&ctx, ev, 525, None, start);
            }
        }
    })
}

// ---------------------------------------------------------------- transparent HTTPS

async fn transparent_tls(mut stream: TcpStream, client: IpAddr, ctx: Arc<ProxyCtx>) {
    let start = Instant::now();
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let host = loop {
        let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
            Ok(Ok(n)) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        match sni::parse_client_hello(&buf) {
            sni::Hello::Incomplete if buf.len() < 16 * 1024 => continue,
            sni::Hello::Sni(Some(h)) => break h,
            _ => {
                tracing::debug!("{client} : pas de SNI, connexion fermée");
                return;
            }
        }
    };
    let host = normalize_host(&host);
    let ev = base_event(client, "TLS", Scheme::Tunnel, &host, 443);

    if let Some(r) = ctx.filter.load().check_domain(&host) {
        emit_now(&ctx, ev, 403, Some(&r), start);
        return;
    }
    if ctx.should_mitm(&host, 443) {
        mitm(sni::Prefixed::new(buf, stream), client, host, 443, ev, ctx).await;
        return;
    }
    let upstream = match tokio::time::timeout(
        ctx.connect_timeout,
        TcpStream::connect((host.as_str(), 443)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            let mut ev = ev;
            ev.reason = Some("connexion amont impossible".into());
            emit_now(&ctx, ev, 502, None, start);
            return;
        }
    };
    let _ = upstream.set_nodelay(true);
    let mut upstream = upstream;
    if upstream.write_all(&buf).await.is_err() {
        return;
    }
    let mut ev = ev;
    ev.bytes_up = buf.len() as u64;
    splice(stream, upstream, ev, 200, start, &ctx).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authority() {
        assert_eq!(
            split_authority("Example.com:8443", 443),
            ("example.com".into(), 8443)
        );
        assert_eq!(
            split_authority("example.com", 80),
            ("example.com".into(), 80)
        );
        assert_eq!(split_authority("[::1]:8080", 80), ("::1".into(), 8080));
    }

    #[test]
    fn sniff_sees_compressed_and_deep_signatures() {
        use std::io::Write;
        // Exécutable servi en gzip, flux tronqué : le début décompressé suffit.
        let mut payload = b"MZ\x90\x00".to_vec();
        payload.extend(std::iter::repeat_n(7u8, 100_000));
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&payload).unwrap();
        let gz = enc.finish().unwrap();
        let head = decoded_head(Some("gzip"), &gz[..gz.len() / 2]).unwrap();
        assert!(head.starts_with(b"MZ"));
        assert!(head.len() <= SNIFF_LEN);
        assert!(decoded_head(Some("br"), &gz).is_none());
        // Image ISO : signature à 0x8001, dans la fenêtre inspectée.
        let mut iso = vec![0u8; SNIFF_LEN];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(
            crate::filter::magic::detect(&iso),
            Some(crate::filter::magic::Kind::Iso)
        );
    }
}
