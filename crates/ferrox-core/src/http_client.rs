//! Client HTTP/HTTPS amont (pool de connexions partagé).

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Limited};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use std::time::Duration;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;
pub type HttpsClient = Client<HttpsConnector<HttpConnector>, ProxyBody>;

pub fn build() -> HttpsClient {
    build_with_timeout(Duration::from_secs(8))
}

pub fn build_with_timeout(connect_timeout: Duration) -> HttpsClient {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);
    http.set_connect_timeout(Some(connect_timeout));
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(32)
        .build(https)
}

pub fn empty() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// GET simple avec suivi de redirections et taille maximale.
pub async fn fetch(client: &HttpsClient, url: &str, max_bytes: usize) -> anyhow::Result<Bytes> {
    let mut url = url.to_string();
    for _ in 0..5 {
        let req = hyper::Request::get(&url)
            .header(
                hyper::header::USER_AGENT,
                concat!("Ferrox/", env!("CARGO_PKG_VERSION")),
            )
            .body(empty())?;
        let resp = tokio::time::timeout(Duration::from_secs(60), client.request(req)).await??;
        let status = resp.status();
        if status.is_redirection() {
            let loc = resp
                .headers()
                .get(hyper::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| anyhow::anyhow!("redirection sans Location"))?;
            let base: hyper::Uri = url.parse()?;
            url = if loc.starts_with("http") {
                loc.to_string()
            } else {
                format!(
                    "{}://{}{}",
                    base.scheme_str().unwrap_or("https"),
                    base.authority().map(|a| a.as_str()).unwrap_or(""),
                    loc
                )
            };
            continue;
        }
        if !status.is_success() {
            anyhow::bail!("HTTP {status}");
        }
        let body = Limited::new(resp.into_body(), max_bytes)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("lecture : {e}"))?
            .to_bytes();
        return Ok(body);
    }
    anyhow::bail!("trop de redirections")
}
