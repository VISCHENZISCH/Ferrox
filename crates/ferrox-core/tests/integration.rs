//! Tests d'intégration : moteur complet sur la boucle locale, ports attribués par le système.
//!
//! Chaque test démarre un `Engine` isolé (dossier de données temporaire, aucune liste
//! téléchargée), des serveurs factices (HTTP, écho TCP, DNS amont) et parle au proxy
//! ou au résolveur comme le ferait un client réel.

use ferrox_core::config::{Config, ProxyAuth};
use ferrox_core::dns::upstream::UpstreamKind;
use ferrox_core::{Engine, Paths};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

const T: Duration = Duration::from_secs(5);

fn temp_dir() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!(
        "ferrox-it-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Configuration minimale : écoute sur des ports libres, ni listes ni journaux.
fn base_config() -> Config {
    let mut c = Config::default();
    c.proxy.listen = "127.0.0.1:0".into();
    c.dns.listen = "127.0.0.1:0".into();
    c.dns.enabled = false;
    c.filter.lists.clear();
    c.log.jsonl = false;
    c
}

fn start(cfg: &Config) -> (Engine, PathBuf) {
    let dir = temp_dir();
    let paths = Paths {
        config_file: dir.join("config.toml"),
        data_dir: dir.clone(),
    };
    (
        Engine::start(cfg, &paths).expect("démarrage du moteur"),
        dir,
    )
}

fn addr_of(engine: &Engine, name: &str) -> SocketAddr {
    engine
        .listeners
        .iter()
        .find(|(n, _)| n.starts_with(name))
        .map(|(_, a)| a.parse().unwrap())
        .unwrap_or_else(|| panic!("écouteur {name} absent : {:?}", engine.listeners))
}

/// Serveur HTTP factice : répond « ok » à toute requête, sur autant de connexions que voulu.
fn http_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                let _ = s.set_read_timeout(Some(T));
                let mut req = Vec::new();
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok",
                );
            });
        }
    });
    a
}

/// Serveur d'écho TCP : renvoie tout ce qu'il reçoit.
fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = s.try_clone().unwrap();
                let mut w = s;
                let _ = std::io::copy(&mut r, &mut w);
            });
        }
    });
    a
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect_timeout(&addr, T).unwrap();
    s.set_read_timeout(Some(T)).unwrap();
    s
}

/// Lit une réponse HTTP jusqu'à la fin des en-têtes (et le corps si Content-Length).
fn read_response(s: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
        let text = String::from_utf8_lossy(&out);
        if let Some(i) = text.find("\r\n\r\n") {
            let len = text[..i]
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if out.len() >= i + 4 + len {
                break;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn status(resp: &str) -> u16 {
    resp.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn get(proxy: SocketAddr, url: &str, extra: &str) -> String {
    let mut s = connect(proxy);
    write!(
        s,
        "GET {url} HTTP/1.1\r\nHost: x\r\nUser-Agent: test\r\nConnection: close\r\n{extra}\r\n"
    )
    .unwrap();
    read_response(&mut s)
}

// ---------------------------------------------------------------- proxy

#[test]
fn proxy_forwards_and_blocks() {
    let upstream = http_server();
    let mut cfg = base_config();
    cfg.filter.custom_block = vec!["blocked.test".into()];
    let (engine, _d) = start(&cfg);
    let proxy = addr_of(&engine, "Proxy");

    let r = get(proxy, &format!("http://{upstream}/hello"), "");
    assert_eq!(status(&r), 200, "{r}");
    assert!(r.ends_with("ok"), "{r}");

    let r = get(proxy, "http://www.blocked.test/", "");
    assert_eq!(status(&r), 403, "{r}");
    assert!(r.contains("Bloqué par Ferrox"));
}

#[test]
fn proxy_refuses_client_outside_allow_list() {
    let upstream = http_server();
    let mut cfg = base_config();
    // Seul 10.0.0.0/8 est autorisé : le test, sur 127.0.0.1, doit être refusé.
    cfg.proxy.allow = vec!["10.0.0.0/8".into()];
    let (engine, _d) = start(&cfg);
    let proxy = addr_of(&engine, "Proxy");

    let mut s = connect(proxy);
    let _ = write!(
        s,
        "GET http://{upstream}/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    );
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "aucune réponse attendue, reçu {n} octets");
}

#[test]
fn connect_limited_to_allowed_ports() {
    let echo = echo_server();
    let mut cfg = base_config();
    cfg.proxy.connect_ports = vec![443, echo.port()];
    let (engine, _d) = start(&cfg);
    let proxy = addr_of(&engine, "Proxy");

    // Port non listé (relais SMTP typique) : refusé.
    let mut s = connect(proxy);
    write!(
        s,
        "CONNECT 127.0.0.1:25 HTTP/1.1\r\nHost: 127.0.0.1:25\r\n\r\n"
    )
    .unwrap();
    assert_eq!(status(&read_response(&mut s)), 403);

    // Port listé : tunnel établi, l'écho revient.
    let mut s = connect(proxy);
    write!(s, "CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").unwrap();
    assert_eq!(status(&read_response(&mut s)), 200);
    s.write_all(b"ping").unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");

    // Débit en temps réel : les octets du tunnel encore ouvert sont déjà comptés.
    let t = engine
        .snapshot(ferrox_core::SnapshotOpts {
            recent: 0,
            alerts: 0,
            series: 0,
            top: 0,
        })
        .totals;
    assert!(t.live_bytes_up >= 4 && t.live_bytes_down >= 4, "{t:?}");

    // Rechargement du filtrage à chaud : le tunnel ouvert continue (ENF-06).
    let mut f = cfg.filter.clone();
    f.custom_block.push("autre.test".into());
    engine.reload_filter(&f);
    s.write_all(b"pong").unwrap();
    s.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"pong");
}

#[test]
fn basic_auth_required_when_configured() {
    let upstream = http_server();
    let mut cfg = base_config();
    cfg.proxy.auth = Some(ProxyAuth {
        user: "alice".into(),
        password: "s3cret".into(),
    });
    let (engine, _d) = start(&cfg);
    let proxy = addr_of(&engine, "Proxy");
    let url = format!("http://{upstream}/");

    let r = get(proxy, &url, "");
    assert_eq!(status(&r), 407, "{r}");
    assert!(r.to_ascii_lowercase().contains("proxy-authenticate: basic"));

    let r = get(
        proxy,
        &url,
        "Proxy-Authorization: Basic YWxpY2U6bm9wZQ==\r\n",
    );
    assert_eq!(status(&r), 407);

    // base64("alice:s3cret")
    let r = get(
        proxy,
        &url,
        "Proxy-Authorization: Basic YWxpY2U6czNjcmV0\r\n",
    );
    assert_eq!(status(&r), 200, "{r}");
}

#[test]
fn tunnel_closes_after_idle_timeout() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        use tokio::io::AsyncWriteExt;
        let (client, mut client_far) = tokio::io::duplex(1024);
        let (server, _server_far) = tokio::io::duplex(1024);
        client_far.write_all(b"abc").await.unwrap();
        let started = std::time::Instant::now();
        let (up, down) =
            ferrox_core::proxy::splice_idle(client, server, Duration::from_millis(100)).await;
        assert_eq!((up, down), (3, 0));
        assert!(started.elapsed() < Duration::from_secs(2));
    });
}

// ---------------------------------------------------------------- DNS

/// Résolveur amont factice : répond 192.0.2.1 à toute question A.
fn fake_upstream() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let a = s.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = s.recv_from(&mut buf) {
            let Ok(req) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let mut m = Message::new();
            m.set_id(req.id())
                .set_message_type(MessageType::Response)
                .set_op_code(OpCode::Query)
                .set_recursion_available(true);
            for q in req.queries() {
                m.add_query(q.clone());
                if q.query_type() == RecordType::A {
                    m.add_answer(Record::from_rdata(
                        q.name().clone(),
                        300,
                        RData::A(A::from(Ipv4Addr::new(192, 0, 2, 1))),
                    ));
                }
            }
            let _ = s.send_to(&m.to_vec().unwrap(), peer);
        }
    });
    a
}

fn query(name: &str, id: u16) -> Vec<u8> {
    let mut m = Message::new();
    m.set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    m.to_vec().unwrap()
}

fn ask_udp(server: SocketAddr, name: &str) -> Option<Message> {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    s.send_to(&query(name, 0x1234), server).unwrap();
    let mut buf = [0u8; 4096];
    let n = s.recv(&mut buf).ok()?;
    Message::from_vec(&buf[..n]).ok()
}

fn ask_tcp(server: SocketAddr, name: &str) -> Option<Message> {
    let mut s = connect(server);
    let q = query(name, 0x4321);
    let mut out = (q.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&q);
    s.write_all(&out).ok()?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len).ok()?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut buf).ok()?;
    Message::from_vec(&buf).ok()
}

fn dns_config(upstream: SocketAddr) -> Config {
    let mut cfg = base_config();
    cfg.proxy.enabled = false;
    cfg.dns.enabled = true;
    cfg.dns.upstreams = vec![upstream.to_string()];
    cfg.filter.custom_block = vec!["blocked.test".into()];
    cfg
}

#[test]
fn dns_resolves_caches_and_blocks() {
    let up = fake_upstream();
    let (engine, _d) = start(&dns_config(up));
    let dns = addr_of(&engine, "DNS");

    let m = ask_udp(dns, "example.test.").expect("réponse UDP");
    assert_eq!(m.id(), 0x1234);
    assert_eq!(m.response_code(), ResponseCode::NoError);
    assert_eq!(m.answers().len(), 1);

    // Deuxième fois : servie par le cache, avec l'identifiant de la nouvelle requête.
    let m = ask_tcp(dns, "example.test.").expect("réponse TCP");
    assert_eq!(m.id(), 0x4321);
    assert_eq!(m.answers().len(), 1);

    let m = ask_udp(dns, "ads.blocked.test.").expect("réponse au domaine bloqué");
    assert_eq!(m.response_code(), ResponseCode::NXDomain);
}

#[test]
fn dns_ignores_clients_outside_allow_list() {
    let up = fake_upstream();
    let mut cfg = dns_config(up);
    cfg.dns.allow = vec!["192.168.0.0/16".into()];
    let (engine, _d) = start(&cfg);
    let dns = addr_of(&engine, "DNS");
    assert!(ask_udp(dns, "example.test.").is_none());
    assert!(ask_tcp(dns, "example.test.").is_none());
}

#[test]
fn ipv6_upstream_without_port_is_accepted() {
    assert_eq!(
        ferrox_core::engine::parse_upstream("2606:4700::1111").unwrap(),
        UpstreamKind::Plain("[2606:4700::1111]:53".parse().unwrap())
    );
    assert_eq!(
        ferrox_core::engine::parse_upstream("1.1.1.1").unwrap(),
        UpstreamKind::Plain("1.1.1.1:53".parse().unwrap())
    );
    assert!(ferrox_core::engine::parse_upstream("pas-une-ip").is_err());

    // Une valeur invalide arrête le démarrage au lieu d'être ignorée.
    let mut cfg = dns_config("127.0.0.1:53".parse().unwrap());
    cfg.dns.upstreams.push("n'importe quoi".into());
    let dir = temp_dir();
    let paths = Paths {
        config_file: dir.join("c.toml"),
        data_dir: dir,
    };
    assert!(Engine::start(&cfg, &paths).is_err());
}

// ---------------------------------------------------------------- 0.3 à 1.0

/// Attend qu'une condition devienne vraie (le pipeline écrit chaque seconde).
fn wait_for(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..40 {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn pac_file_served_without_auth() {
    let mut cfg = base_config();
    cfg.proxy.auth = Some(ProxyAuth {
        user: "alice".into(),
        password: "x".into(),
    });
    let (engine, _d) = start(&cfg);
    let proxy = addr_of(&engine, "Proxy");
    let mut s = connect(proxy);
    write!(
        s,
        "GET /proxy.pac HTTP/1.1\r\nHost: 192.168.1.5:3128\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let r = read_response(&mut s);
    assert_eq!(status(&r), 200, "{r}");
    assert!(r.contains("application/x-ns-proxy-autoconfig"));
    assert!(r.contains("PROXY 192.168.1.5:3128"), "{r}");
}

#[test]
fn logs_are_ecs_json_and_queries_masked() {
    let upstream = http_server();
    let mut cfg = base_config();
    cfg.log.jsonl = true;
    cfg.log.mask_query = true;
    let (engine, dir) = start(&cfg);
    let proxy = addr_of(&engine, "Proxy");
    let r = get(proxy, &format!("http://{upstream}/p?token=secret&x=1"), "");
    assert_eq!(status(&r), 200);
    let logs = dir.join("logs");
    let read_all = || -> String {
        std::fs::read_dir(&logs)
            .map(|d| {
                d.flatten()
                    .filter(|e| e.file_name().to_string_lossy().starts_with("traffic-"))
                    .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
                    .collect()
            })
            .unwrap_or_default()
    };
    assert!(
        wait_for(|| read_all().contains("token=*")),
        "{}",
        read_all()
    );
    let text = read_all();
    assert!(!text.contains("secret"));
    // ENF-11 : chaque ligne est un document JSON avec @timestamp et la version ECS.
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON valide");
        assert!(v["@timestamp"].is_string());
        assert_eq!(v["ecs"]["version"], ferrox_core::logger::ECS_VERSION);
    }
}

#[test]
fn history_records_minutes() {
    let upstream = http_server();
    let cfg = base_config();
    let (engine, _d) = start(&cfg);
    let proxy = addr_of(&engine, "Proxy");
    for _ in 0..3 {
        assert_eq!(status(&get(proxy, &format!("http://{upstream}/"), "")), 200);
    }
    let path = engine
        .history_path()
        .expect("historique actif")
        .to_path_buf();
    let now = ferrox_core::event::now_ms();
    assert!(wait_for(|| {
        ferrox_core::history::HistoryReader::open(&path)
            .and_then(|r| r.totals(now - 120_000, now + 120_000))
            .is_ok_and(|t| t.totals.requests >= 3)
    }));
}

#[test]
fn rules_reload_without_restart() {
    let cfg = base_config();
    let (engine, dir) = start(&cfg);
    let proxy = addr_of(&engine, "Proxy");
    // Fichier d'exemple créé au premier démarrage.
    let rules = dir.join("rules.toml");
    assert!(rules.exists());
    assert!(engine.info().rules_loaded >= 3);

    std::fs::write(
        &rules,
        "[[rule]]\nid = \"lab\"\nname = \"Hôte de laboratoire\"\nseverity = \"critical\"\n\
         [rule.match]\nhost = [\"lab.invalid\"]\n",
    )
    .unwrap();
    engine.reload_rules();
    assert!(wait_for(|| engine.info().rules_loaded == 1));

    let _ = get(proxy, "http://www.lab.invalid/", "");
    let stats = engine.stats();
    assert!(wait_for(|| stats.alerts_since(0).iter().any(|a| a
        .rule
        .as_deref()
        == Some("lab")
        && a.severity == ferrox_core::event::Severity::Critical)));

    // Fichier invalide : les règles précédentes restent, l'erreur est signalée.
    std::fs::write(&rules, "[[rule]]\nid = 3").unwrap();
    engine.reload_rules();
    assert!(wait_for(|| engine.info().rules_error.is_some()));
    assert_eq!(engine.info().rules_loaded, 1);
}

fn http_get_raw(addr: SocketAddr, path: &str, extra: &str) -> String {
    let mut s = connect(addr);
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n{extra}\r\n"
    )
    .unwrap();
    read_response(&mut s)
}

#[test]
fn api_and_metrics_with_token() {
    let upstream = http_server();
    let mut cfg = base_config();
    cfg.api.enabled = true;
    cfg.api.listen = "127.0.0.1:0".into();
    cfg.api.token = Some("t0k".into());
    let (engine, _d) = start(&cfg);
    let proxy = addr_of(&engine, "Proxy");
    let api = addr_of(&engine, "API");
    assert_eq!(status(&get(proxy, &format!("http://{upstream}/"), "")), 200);

    assert_eq!(status(&http_get_raw(api, "/metrics", "")), 401);
    let auth = "Authorization: Bearer t0k\r\n";
    assert!(wait_for(
        || http_get_raw(api, "/metrics", auth).contains("ferrox_http_requests_total 1")
    ));
    let r = http_get_raw(api, "/api/v1/health", auth);
    assert_eq!(status(&r), 200);
    assert!(r.contains("\"status\":\"ok\""));
    let r = http_get_raw(api, "/api/v1/status", auth);
    assert!(r.contains("\"listeners\""), "{r}");
    let r = http_get_raw(api, "/api/v1/history/series?hours=1&step=10", auth);
    assert_eq!(status(&r), 200, "{r}");
    assert_eq!(status(&http_get_raw(api, "/nope", auth)), 404);
}

#[test]
fn intercepted_clients_can_speak_http2() {
    let mut cfg = base_config();
    cfg.tls.mitm = true;
    let (engine, _d) = start(&cfg);
    let proxy = addr_of(&engine, "Proxy");
    let ca_pem = std::fs::read(engine.ca_cert_path().unwrap()).unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(proxy).await.unwrap();
        s.write_all(
            b"CONNECT unreachable.invalid:443 HTTP/1.1\r\nHost: unreachable.invalid:443\r\n\r\n",
        )
        .await
        .unwrap();
        let mut buf = vec![0u8; 256];
        let n = s.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));

        let mut roots = rustls::RootCertStore::empty();
        let der: String = String::from_utf8(ca_pem)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD
            .decode(der)
            .unwrap();
        roots.add(der.into()).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let conn = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls));
        let name = rustls::pki_types::ServerName::try_from("unreachable.invalid").unwrap();
        let tls = conn
            .connect(name, s)
            .await
            .expect("poignée de main interceptée");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));

        let (mut send, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(tls),
        )
        .await
        .unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::get("https://unreachable.invalid/")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let resp = send.send_request(req).await.unwrap();
        assert_eq!(resp.version(), hyper::Version::HTTP_2);
        // L'amont n'existe pas : Ferrox répond lui-même, en HTTP/2.
        assert_eq!(resp.status(), 502);
    });
}
