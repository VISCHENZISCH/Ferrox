//! Serveur DNS intégré : filtrage, cache, relais vers les résolveurs amont (UDP et TCP).

use crate::config::DnsBlockMode;
use crate::event::{now_ms, Action, DnsEvent, Event, EventSink};
use crate::filter::{normalize_host, Filter};
use dashmap::DashMap;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

struct CacheEntry {
    bytes: Vec<u8>,
    expires: Instant,
    rcode: ResponseCode,
    answers: u16,
}

pub struct DnsCtx {
    pub filter: Arc<Filter>,
    pub sink: EventSink,
    pub upstreams: Vec<SocketAddr>,
    pub block_mode: DnsBlockMode,
    pub cache_max: usize,
    pub timeout: Duration,
    cache: DashMap<(Box<str>, u16), CacheEntry>,
}

impl DnsCtx {
    pub fn new(
        filter: Arc<Filter>,
        sink: EventSink,
        upstreams: Vec<SocketAddr>,
        block_mode: DnsBlockMode,
        cache_max: usize,
        timeout: Duration,
    ) -> Self {
        Self {
            filter,
            sink,
            upstreams,
            block_mode,
            cache_max,
            timeout,
            cache: DashMap::new(),
        }
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

pub async fn run_tcp(listener: TcpListener, ctx: Arc<DnsCtx>) {
    loop {
        let Ok((mut stream, peer)) = listener.accept().await else {
            continue;
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            loop {
                let len =
                    match tokio::time::timeout(Duration::from_secs(10), stream.read_u16()).await {
                        Ok(Ok(l)) => l as usize,
                        _ => return,
                    };
                let mut pkt = vec![0u8; len];
                if stream.read_exact(&mut pkt).await.is_err() {
                    return;
                }
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

    // Cache.
    let key = (qname.clone().into_boxed_str(), u16::from(qtype));
    if let Some(e) = ctx.cache.get(&key) {
        if e.expires > Instant::now() {
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
        let r = match transport {
            Transport::Udp => forward_udp(pkt, *up, ctx.timeout).await,
            Transport::Tcp => forward_tcp(pkt, *up, ctx.timeout).await,
        };
        if let Ok(r) = r {
            resp = Some(r);
            break;
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
    finish(ev, rcode, answers);
    Some(bytes)
}

async fn forward_udp(pkt: &[u8], up: SocketAddr, timeout: Duration) -> std::io::Result<Vec<u8>> {
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
        if n >= 2 && buf[..2] == pkt[..2] {
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
