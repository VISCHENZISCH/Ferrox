//! Extraction du SNI d'un ClientHello TLS, et flux « préfixé » permettant
//! de rejouer les octets déjà lus.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum Hello {
    Incomplete,
    NotTls,
    Sni(Option<String>),
}

pub fn parse_client_hello(buf: &[u8]) -> Hello {
    if buf.is_empty() {
        return Hello::Incomplete;
    }
    if buf[0] != 0x16 {
        return Hello::NotTls;
    }
    if buf.len() < 5 {
        return Hello::Incomplete;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + rec_len {
        return Hello::Incomplete;
    }
    let h = &buf[5..5 + rec_len];
    match parse_handshake(h) {
        Some(s) => Hello::Sni(s),
        None => Hello::NotTls,
    }
}

fn parse_handshake(h: &[u8]) -> Option<Option<String>> {
    let mut r = Reader { b: h, p: 0 };
    if r.u8()? != 0x01 {
        return None;
    }
    r.skip(3)?; // longueur du message
    r.skip(2 + 32)?; // version + aléa
    let sid = r.u8()? as usize;
    r.skip(sid)?;
    let cs = r.u16()? as usize;
    r.skip(cs)?;
    let comp = r.u8()? as usize;
    r.skip(comp)?;
    if r.remaining() == 0 {
        return Some(None);
    }
    let ext_total = r.u16()? as usize;
    let end = (r.p + ext_total).min(h.len());
    while r.p + 4 <= end {
        let ty = r.u16()?;
        let len = r.u16()? as usize;
        if ty == 0 {
            let mut s = Reader {
                b: r.take(len)?,
                p: 0,
            };
            let _list = s.u16()?;
            while s.remaining() >= 3 {
                let name_type = s.u8()?;
                let nlen = s.u16()? as usize;
                let name = s.take(nlen)?;
                if name_type == 0 {
                    return Some(
                        std::str::from_utf8(name)
                            .ok()
                            .map(|n| n.to_ascii_lowercase()),
                    );
                }
            }
            return Some(None);
        }
        r.skip(len)?;
    }
    Some(None)
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.p)
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.p)?;
        self.p += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        let s = self.b.get(self.p..self.p + 2)?;
        self.p += 2;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        if self.remaining() < n {
            return None;
        }
        self.p += n;
        Some(())
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.p..self.p + n)?;
        self.p += n;
        Some(s)
    }
}

/// Flux qui restitue d'abord `prefix`, puis lit le flux sous-jacent.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let n = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, b)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ClientHello minimal avec SNI "example.com".
    fn hello(name: &str) -> Vec<u8> {
        let n = name.as_bytes();
        let mut sni = vec![];
        sni.extend_from_slice(&((n.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(n.len() as u16).to_be_bytes());
        sni.extend_from_slice(n);
        let mut ext = vec![0, 0];
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // suites
        body.extend_from_slice(&[1, 0]); // compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn sni() {
        let h = hello("Example.com");
        assert_eq!(
            parse_client_hello(&h),
            Hello::Sni(Some("example.com".into()))
        );
        assert_eq!(parse_client_hello(&h[..10]), Hello::Incomplete);
        assert_eq!(parse_client_hello(b"GET / HTTP/1.1"), Hello::NotTls);
    }
}
