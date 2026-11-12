//! Serveur DNS intégré : filtrage, cache, relais vers les résolveurs amont
//! (UDP, TCP, DNS sur TLS, DNS sur HTTPS).

pub mod upstream;

use crate::access::{client_allowed, Cidr};
use crate::config::DnsBlockMode;
use crate::event::{now_ms, Action, DnsEvent, Event, EventSink};
use crate::filter::{normalize_host, Filter};
use dashmap::DashMap;
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use upstream::Upstream;

/// Délai pour lire un message DNS complet sur TCP (RFC 7766).
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(10);

struct CacheEntry {
    bytes: Vec<u8>,
    expires: Instant,
    rcode: ResponseCode,
    answers: u16,
}

pub struct DnsCtx {
    pub filter: Arc<Filter>,
    pub sink: EventSink,
    pub upstreams: Vec<Upstream>,
    pub block_mode: DnsBlockMode,
    pub cache_max: usize,
    pub timeout: Duration,
    /// Réseaux clients autorisés (résolveur ouvert sinon : amplification).
    pub allow: Vec<Cidr>,
    /// Plafond de connexions TCP simultanées.
    pub max_tcp_clients: usize,
    cache: DashMap<(Box<str>, u16), CacheEntry>,
    tls: tokio_rustls::TlsConnector,
    https: crate::http_client::HttpsClient,
}

impl DnsCtx {
    pub fn new(
        filter: Arc<Filter>,
        sink: EventSink,
        upstreams: Vec<upstream::UpstreamKind>,
        block_mode: DnsBlockMode,
        cache_max: usize,
        timeout: Duration,
    ) -> Self {
        let encrypted = upstreams
            .iter()
            .any(|u| !matches!(u, upstream::UpstreamKind::Plain(_)));
        if encrypted {
            crate::install_crypto_provider();
        }
        Self {
            filter,
            sink,
            upstreams: upstreams.into_iter().map(Upstream::new).collect(),
            block_mode,
            cache_max,
            timeout,
            allow: crate::access::loopback(),
            max_tcp_clients: 256,
            cache: DashMap::new(),
            tls: upstream::dot_connector(),
            https: upstream::doh_client(),
        }
    }

    /// Réseaux autorisés et plafond TCP.
    #[must_use]
    pub fn with_access(mut self, allow: Vec<Cidr>, max_tcp_clients: usize) -> Self {
        self.allow = allow;
        self.max_tcp_clients = max_tcp_clients.max(1);
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

pub fn rcode_str(rc: ResponseCode) -> String {
    match rc {
        ResponseCode::NoError => "NOERROR".into(),
        ResponseCode::NXDomain => "NXDOMAIN".into(),
        ResponseCode::ServFail => "SERVFAIL".into(),
        ResponseCode::Refused => "REFUSED".into(),
        ResponseCode::FormErr => "FORMERR".into(),
        other => format!("RCODE{}", u16::from(other)),
    }
}

pub async fn run_udp(sock: Arc<UdpSocket>, ctx: Arc<DnsCtx>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("dns recv : {e}");
                continue;
            }
        };
        if !client_allowed(peer.ip(), &ctx.allow) {
            // Aucune réponse : un refus explicite servirait encore à l'amplification.
            continue;
        }
        let pkt = buf[..n].to_vec();
        let sock = sock.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Some(resp) = resolve(&pkt, peer.ip(), &ctx, Transport::Udp).await {
                let _ = sock.send_to(&resp, peer).await;
            }
        });
    }
}

/// Lit un message DNS sur TCP avec un délai sur toute la lecture (longueur et contenu).
async fn read_msg(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let fut = async {
        let len = stream.read_u16().await.ok()? as usize;
        let mut pkt = vec![0u8; len];
        stream.read_exact(&mut pkt).await.ok()?;
        Some(pkt)
    };
    tokio::time::timeout(TCP_READ_TIMEOUT, fut)
        .await
        .ok()
        .flatten()
}

pub async fn run_tcp(listener: TcpListener, ctx: Arc<DnsCtx>) {
    let slots = Arc::new(Semaphore::new(ctx.max_tcp_clients));
    loop {
        let Ok((mut stream, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        if !client_allowed(peer.ip(), &ctx.allow) {
            continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue; // trop de connexions : la nouvelle est fermée
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            while let Some(pkt) = read_msg(&mut stream).await {
                if let Some(resp) = resolve(&pkt, peer.ip(), &ctx, Transport::Tcp).await {
                    let mut out = Vec::with_capacity(resp.len() + 2);
                    out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
                    out.extend_from_slice(&resp);
                    if stream.write_all(&out).await.is_err() {
                        return;
                    }
                }
            }
        });
    }
}

fn reply_base(req: &Message) -> Message {
    let mut m = Message::new();
    m.set_id(req.id())
        .set_message_type(MessageType::Response)
        .set_op_code(req.op_code())
        .set_recursion_desired(req.recursion_desired())
        .set_recursion_available(true);
    for q in req.queries() {
        m.add_query(q.clone());
    }
    m
}

async fn resolve(
    pkt: &[u8],
    client: IpAddr,
    ctx: &DnsCtx,
    transport: Transport,
) -> Option<Vec<u8>> {
    let start = Instant::now();
    let req = Message::from_vec(pkt).ok()?;
    let q = req.queries().first()?.clone();
    let qname = normalize_host(&q.name().to_ascii());
    let qtype = q.query_type();
    let mut ev = DnsEvent {
        ts: now_ms(),
        client,
        qname: qname.clone(),
        qtype: qtype.to_string(),
        rcode: String::new(),
        answers: 0,
        latency_ms: 0,
        cached: false,
        action: Action::Allow,
        reason: None,
        category: None,
    };
    let finish = |mut ev: DnsEvent, rcode: ResponseCode, answers: u16| {
        ev.rcode = rcode_str(rcode);
        ev.answers = answers;
        ev.latency_ms = start.elapsed().as_millis().min(u32::MAX as u128) as u32;
        ctx.sink.emit(Event::Dns(ev));
    };

    // Filtrage.
    if let Some(r) = ctx.filter.load().check_domain(&qname) {
        let mut m = reply_base(&req);
        let mut answers = 0;
        let rcode = match ctx.block_mode {
            DnsBlockMode::Nxdomain => ResponseCode::NXDomain,
            DnsBlockMode::Sinkhole => {
                let rdata = match qtype {
                    RecordType::A => Some(RData::A(A::from(Ipv4Addr::UNSPECIFIED))),
                    RecordType::AAAA => Some(RData::AAAA(AAAA::from(Ipv6Addr::UNSPECIFIED))),
                    _ => None,
                };
                if let Some(rd) = rdata {
                    m.add_answer(Record::from_rdata(q.name().clone(), 60, rd));
                    answers = 1;
                }
                ResponseCode::NoError
            }
        };
        m.set_response_code(rcode);
        ev.action = Action::Block;
        ev.reason = Some(r.reason);
        ev.category = Some(r.category);
        finish(ev, rcode, answers);
        return m.to_vec().ok();
    }

    // Taille de réponse acceptée par le client en UDP (512, ou annoncée par EDNS).
    let udp_limit = req
        .extensions()
        .as_ref()
        .map_or(512, |e| usize::from(e.max_payload()))
        .max(512);

    // Cache.
    let key = (qname.clone().into_boxed_str(), u16::from(qtype));
    if let Some(e) = ctx.cache.get(&key) {
        if e.expires > Instant::now() {
            if transport == Transport::Udp && e.bytes.len() > udp_limit {
                // Réponse obtenue en TCP, trop grande pour ce client : TC=1, il réessaiera en TCP.
                drop(e);
                let mut m = reply_base(&req);
                m.set_truncated(true);
                ev.cached = true;
                finish(ev, ResponseCode::NoError, 0);
                return m.to_vec().ok();
            }
            let mut b = e.bytes.clone();
            b[0] = pkt[0];
            b[1] = pkt[1];
            ev.cached = true;
            let (rc, an) = (e.rcode, e.answers);
            drop(e);
            finish(ev, rc, an);
            return Some(b);
        }
    }

    // Relais amont.
    let mut resp = None;
    for up in &ctx.upstreams {
        let r = match (up.plain_addr(), transport) {
            (Some(a), Transport::Udp) => forward_udp(pkt, req.queries(), a, ctx.timeout).await,
            (Some(a), Transport::Tcp) => forward_tcp(pkt, a, ctx.timeout).await,
            (None, _) => up
                .exchange_encrypted(pkt, &ctx.tls, &ctx.https, ctx.timeout)
                .await
                .and_then(|r| {
                    // Même contrôle que pour l'UDP : identifiant et question.
                    if matches_query(&r, pkt, req.queries()) {
                        Ok(r)
                    } else {
                        Err(std::io::Error::other("réponse DoT/DoH sans rapport"))
                    }
                }),
        };
        match r {
            Ok(r) => {
                resp = Some(r);
                break;
            }
            Err(e) => tracing::debug!("DNS amont {} : {e}", up.kind),
        }
    }
    let Some(bytes) = resp else {
        let mut m = reply_base(&req);
        m.set_response_code(ResponseCode::ServFail);
        ev.reason = Some("résolveurs amont injoignables".into());
        finish(ev, ResponseCode::ServFail, 0);
        return m.to_vec().ok();
    };

    let (rcode, answers) = match Message::from_vec(&bytes) {
        Ok(m) => {
            let rc = m.response_code();
            let an = m.answers().len() as u16;
            if !m.truncated() && matches!(rc, ResponseCode::NoError | ResponseCode::NXDomain) {
                let ttl = if rc == ResponseCode::NXDomain || m.answers().is_empty() {
                    60
                } else {
                    m.answers()
                        .iter()
                        .map(|r| r.ttl())
                        .min()
                        .unwrap_or(60)
                        .clamp(5, 3600)
                };
                if ctx.cache.len() >= ctx.cache_max {
                    let now = Instant::now();
                    ctx.cache.retain(|_, v| v.expires > now);
                    if ctx.cache.len() >= ctx.cache_max {
                        ctx.cache.clear();
                    }
                }
                ctx.cache.insert(
                    key,
                    CacheEntry {
                        bytes: bytes.clone(),
                        expires: Instant::now() + Duration::from_secs(ttl as u64),
                        rcode: rc,
                        answers: an,
                    },
                );
            }
            (rc, an)
        }
        Err(_) => (ResponseCode::FormErr, 0),
    };
    if transport == Transport::Udp && bytes.len() > udp_limit {
        // Réponse DoT/DoH trop grande pour ce client UDP : TC=1, il réessaiera en TCP.
        let mut m = reply_base(&req);
        m.set_truncated(true);
        finish(ev, rcode, 0);
        return m.to_vec().ok();
    }
    finish(ev, rcode, answers);
    Some(bytes)
}

/// Vrai si la réponse porte le même identifiant et la même question que la requête.
fn matches_query(resp: &[u8], id: &[u8], queries: &[Query]) -> bool {
    resp.len() >= 12
        && resp[..2] == id[..2]
        && Message::from_vec(resp).is_ok_and(|m| m.queries() == queries)
}

async fn forward_udp(
    pkt: &[u8],
    queries: &[Query],
    up: SocketAddr,
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let bind: SocketAddr = if up.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let s = UdpSocket::bind(bind).await?;
    s.connect(up).await?;
    s.send(pkt).await?;
    let mut buf = vec![0u8; 4096];
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let n = tokio::time::timeout(left, s.recv(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dns timeout"))??;
        // Identifiant ET question vérifiés : une réponse forgée doit deviner les deux.
        if matches_query(&buf[..n], pkt, queries) {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

async fn forward_tcp(pkt: &[u8], up: SocketAddr, timeout: Duration) -> std::io::Result<Vec<u8>> {
    let fut = async {
        let mut s = TcpStream::connect(up).await?;
        let mut out = Vec::with_capacity(pkt.len() + 2);
        out.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
        out.extend_from_slice(pkt);
        s.write_all(&out).await?;
        let len = s.read_u16().await? as usize;
        let mut buf = vec![0u8; len];
        s.read_exact(&mut buf).await?;
        Ok(buf)
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dns timeout"))?
}
