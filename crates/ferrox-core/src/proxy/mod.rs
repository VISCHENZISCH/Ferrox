//! Proxy HTTP/HTTPS : mode explicite (HTTP + CONNECT), transparent HTTP,
//! transparent HTTPS (routage par SNI), et interception TLS optionnelle.

pub mod body;
pub mod sni;

use crate::event::{now_ms, Action, Event, EventSink, HttpEvent, Scheme};
use crate::filter::{normalize_host, BlockReason, Filter};
use crate::http_client::{HttpsClient, ProxyBody};
use crate::tls::CertAuthority;
use body::{Counted, EventGuard, Prepend};
use bytes::Bytes;
use dashmap::DashSet;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
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

pub struct ProxyCtx {
    pub filter: Arc<Filter>,
    pub sink: EventSink,
    pub client: HttpsClient,
    pub ca: Option<Arc<CertAuthority>>,
    pub bypass: Vec<String>,
    /// Hôtes dont la poignée de main interceptée a échoué (épinglage) : tunnel direct ensuite.
    pub auto_bypass: DashSet<String>,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub active: Arc<AtomicU64>,
}

impl ProxyCtx {
    fn should_mitm(&self, host: &str, port: u16) -> bool {
        self.ca.is_some()
            && matches!(port, 443 | 8443)
            && !self.auto_bypass.contains(host)
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
                let _ = stream.set_nodelay(true);
                let ctx = ctx.clone();
                let f = f.clone();
                tokio::spawn(async move {
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

    let resp = match tokio::time::timeout(ctx.idle_timeout, ctx.client.request(upstream_req)).await
    {
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

    // Inspection de la signature du fichier sur la première trame.
    let mut rbody = rbody;
    let mut first = None;
    if filter.wants_sniff() && rparts.status.is_success() {
        match rbody.frame().await {
            Some(Ok(frame)) => {
                if let Some(d) = frame.data_ref() {
                    if let Some(r) = filter.check_magic(d) {
                        emit_now(&ctx, ev, 403, Some(&r), start);
                        return block_page(&host, &r);
                    }
                }
                first = Some(frame);
            }
            Some(Err(e)) => {
                ev.reason = Some(format!("amont : {e}"));
                emit_now(&ctx, ev, 502, None, start);
                return simple(StatusCode::BAD_GATEWAY, "Ferrox : réponse amont invalide");
            }
            None => {}
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
    mut a: A,
    mut b: TcpStream,
    mut ev: HttpEvent,
    status: u16,
    start: Instant,
    ctx: &ProxyCtx,
) where
    A: AsyncRead + AsyncWrite + Unpin,
{
    let (up, down) = tokio::io::copy_bidirectional(&mut a, &mut b)
        .await
        .unwrap_or((0, 0));
    ev.bytes_up += up;
    ev.bytes_down += down;
    emit_now(ctx, ev, status, None, start);
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
                // Certificat refusé (épinglage, CA non installée) : tunnel direct la prochaine fois.
                let msg = match other {
                    Ok(Err(e)) => format!("interception refusée : {e}"),
                    _ => "interception : délai dépassé".into(),
                };
                ctx.auto_bypass.insert(host.clone());
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
}
