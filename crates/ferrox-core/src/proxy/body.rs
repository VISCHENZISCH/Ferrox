//! Corps HTTP instrumentés : comptage des octets et émission de l'événement
//! à la fin de l'échange (quand le corps de réponse est libéré).

use crate::event::{Event, EventSink, HttpEvent};
use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

/// Émet l'événement HTTP une seule fois, à sa destruction.
pub struct EventGuard {
    pub ev: Option<HttpEvent>,
    pub start: Instant,
    pub header_up: u64,
    pub up: Arc<AtomicU64>,
    pub down: Arc<AtomicU64>,
    pub sink: EventSink,
}

impl Drop for EventGuard {
    fn drop(&mut self) {
        if let Some(mut ev) = self.ev.take() {
            ev.bytes_up = self.header_up + self.up.load(Ordering::Relaxed);
            ev.bytes_down += self.down.load(Ordering::Relaxed);
            ev.duration_ms = self.start.elapsed().as_millis().min(u32::MAX as u128) as u32;
            self.sink.emit(Event::Http(ev));
        }
    }
}

pub struct Counted<B> {
    inner: B,
    counter: Arc<AtomicU64>,
    _guard: Option<EventGuard>,
}

impl<B> Counted<B> {
    pub fn new(inner: B, counter: Arc<AtomicU64>, guard: Option<EventGuard>) -> Self {
        Self {
            inner,
            counter,
            _guard: guard,
        }
    }
}

impl<B> Body for Counted<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(ref f))) = r {
            if let Some(d) = f.data_ref() {
                this.counter.fetch_add(d.len() as u64, Ordering::Relaxed);
            }
        }
        r
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Réinjecte les premières trames déjà lues (après inspection de signature).
pub struct Prepend<B> {
    first: std::collections::VecDeque<Frame<Bytes>>,
    inner: B,
}

impl<B> Prepend<B> {
    pub fn new(first: Vec<Frame<Bytes>>, inner: B) -> Self {
        Self {
            first: first.into(),
            inner,
        }
    }
}

impl<B> Body for Prepend<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(f) = this.first.pop_front() {
            return Poll::Ready(Some(Ok(f)));
        }
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.first.is_empty() && self.inner.is_end_stream()
    }
}
