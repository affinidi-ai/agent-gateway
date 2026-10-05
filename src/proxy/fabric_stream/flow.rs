use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, watch};

use super::wire::{MAX_CHUNK_BYTES, MAX_WINDOW_BYTES, StreamErrorCode};

const MAX_IN_FLIGHT_FRAMES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Credit {
    pub next_sequence: u64,
    pub consumed_bytes: u64,
}

#[derive(Debug)]
pub(crate) struct SendWindow {
    window_bytes: usize,
    sent: Credit,
    acknowledged: Credit,
    outstanding: VecDeque<Credit>,
}

impl SendWindow {
    pub fn new(window_bytes: usize) -> Result<Self, String> {
        if !(MAX_CHUNK_BYTES..=MAX_WINDOW_BYTES).contains(&window_bytes) {
            return Err("Fabric stream window must accommodate one maximum chunk and stay within its cap".to_string());
        }
        Ok(Self {
            window_bytes,
            sent: Credit {
                next_sequence: 0,
                consumed_bytes: 0,
            },
            acknowledged: Credit {
                next_sequence: 0,
                consumed_bytes: 0,
            },
            outstanding: VecDeque::new(),
        })
    }

    pub fn reserve(
        &mut self,
        bytes: usize,
    ) -> Result<Option<(u64, u64)>, String> {
        if bytes == 0 || bytes > MAX_CHUNK_BYTES {
            return Err("Invalid Fabric stream chunk size".to_string());
        }
        let sent_bytes = self
            .sent
            .consumed_bytes
            .checked_add(bytes as u64)
            .ok_or("Fabric stream byte count overflow")?;
        if sent_bytes
            - self
                .acknowledged
                .consumed_bytes
            > self.window_bytes as u64
            || self.outstanding.len() == MAX_IN_FLIGHT_FRAMES
        {
            return Ok(None);
        }
        let next_sequence = self
            .sent
            .next_sequence
            .checked_add(1)
            .ok_or("Fabric stream sequence overflow")?;
        let reserved = (self.sent.next_sequence, self.sent.consumed_bytes);
        self.sent = Credit {
            next_sequence,
            consumed_bytes: sent_bytes,
        };
        self.outstanding
            .push_back(self.sent);
        Ok(Some(reserved))
    }

    pub fn acknowledge(
        &mut self,
        credit: Credit,
    ) -> Result<bool, String> {
        if credit == self.acknowledged {
            return Ok(false);
        }
        if credit.next_sequence
            < self
                .acknowledged
                .next_sequence
            && credit.consumed_bytes
                <= self
                    .acknowledged
                    .consumed_bytes
        {
            return Ok(false);
        }
        let position = self
            .outstanding
            .iter()
            .position(|sent| *sent == credit)
            .ok_or("Fabric stream credit does not acknowledge an emitted frame boundary")?;
        self.outstanding
            .drain(..=position);
        self.acknowledged = credit;
        Ok(true)
    }

    pub fn sent(&self) -> Credit {
        self.sent
    }
}

/// The end of one wait for a peer's progress: `deadline`, or sooner when a
/// progress timeout is set.
pub(crate) fn progress_deadline(
    progress_timeout: Option<Duration>,
    deadline: tokio::time::Instant,
) -> tokio::time::Instant {
    progress_timeout
        .and_then(|timeout| tokio::time::Instant::now().checked_add(timeout))
        .map_or(deadline, |idle| idle.min(deadline))
}

struct SendState {
    window: SendWindow,
    failure: Option<StreamErrorCode>,
    terminal: Option<Credit>,
    terminal_acknowledged: bool,
}

pub(crate) struct SendCredit {
    state: Mutex<SendState>,
    changed: Notify,
    cancelled: watch::Sender<Option<StreamErrorCode>>,
    /// Longest wait for the peer's next Credit or EndAck while frames are
    /// outstanding; unset, a wait lasts until the stream deadline.
    progress_timeout: OnceLock<Duration>,
}

impl SendCredit {
    pub fn new(window_bytes: usize) -> Result<Self, String> {
        Ok(Self {
            state: Mutex::new(SendState {
                window: SendWindow::new(window_bytes)?,
                failure: None,
                terminal: None,
                terminal_acknowledged: false,
            }),
            changed: Notify::new(),
            cancelled: watch::channel(None).0,
            progress_timeout: OnceLock::new(),
        })
    }

    /// Bounds each wait for the peer's progress, so a peer that stops
    /// acknowledging releases the stream before its deadline. Set once.
    pub fn set_progress_timeout(
        &self,
        timeout: Duration,
    ) {
        let _ = self
            .progress_timeout
            .set(timeout);
    }

    fn wait_deadline(
        &self,
        deadline: tokio::time::Instant,
    ) -> tokio::time::Instant {
        progress_deadline(
            self.progress_timeout
                .get()
                .copied(),
            deadline,
        )
    }

    pub async fn reserve(
        &self,
        bytes: usize,
        deadline: tokio::time::Instant,
    ) -> Result<(u64, u64), StreamErrorCode> {
        loop {
            let notified = self.changed.notified();
            let result = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| StreamErrorCode::Unavailable)?;
                if let Some(error) = state.failure {
                    return Err(error);
                }
                if state.terminal.is_some() {
                    return Err(StreamErrorCode::InvalidFrame);
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(StreamErrorCode::DeadlineExceeded);
                }
                state
                    .window
                    .reserve(bytes)
                    .map_err(|_| StreamErrorCode::InvalidFrame)?
            };
            if let Some(reserved) = result {
                return Ok(reserved);
            }
            tokio::time::timeout_at(self.wait_deadline(deadline), notified)
                .await
                .map_err(|_| StreamErrorCode::DeadlineExceeded)?;
        }
    }

    pub fn acknowledge(
        &self,
        credit: Credit,
    ) -> Result<bool, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Fabric send window is unavailable")?;
        if state.failure.is_some() {
            return Ok(false);
        }
        let result = state
            .window
            .acknowledge(credit);
        if result.is_err() {
            state.failure = Some(StreamErrorCode::InvalidFrame);
            self.cancelled
                .send_replace(state.failure);
        }
        drop(state);
        if !matches!(result, Ok(false)) {
            self.changed.notify_one();
        }
        result
    }

    pub async fn wait_consumed(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), StreamErrorCode> {
        loop {
            let notified = self.changed.notified();
            {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| StreamErrorCode::Unavailable)?;
                if let Some(error) = state.failure {
                    return Err(error);
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(StreamErrorCode::DeadlineExceeded);
                }
                if state
                    .window
                    .outstanding
                    .is_empty()
                    && (state.terminal.is_none() || state.terminal_acknowledged)
                {
                    return Ok(());
                }
            }
            tokio::time::timeout_at(self.wait_deadline(deadline), notified)
                .await
                .map_err(|_| StreamErrorCode::DeadlineExceeded)?;
        }
    }

    pub fn cancel(
        &self,
        code: StreamErrorCode,
    ) {
        if let Ok(mut state) = self.state.lock() {
            state
                .failure
                .get_or_insert(code);
            self.cancelled
                .send_replace(state.failure);
        }
        self.changed.notify_one();
    }

    pub fn cancellation(&self) -> watch::Receiver<Option<StreamErrorCode>> {
        self.cancelled.subscribe()
    }

    pub fn consumed_bytes(&self) -> u64 {
        self.state
            .lock()
            .map_or(0, |state| {
                state
                    .window
                    .acknowledged
                    .consumed_bytes
            })
    }

    pub fn seal(&self) -> Result<Credit, StreamErrorCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StreamErrorCode::Unavailable)?;
        if let Some(error) = state.failure {
            return Err(error);
        }
        let sent = state.window.sent();
        state.terminal = Some(sent);
        Ok(sent)
    }

    pub fn acknowledge_end(
        &self,
        credit: Credit,
    ) -> Result<bool, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Fabric send window is unavailable")?;
        if state.failure.is_some() {
            return Ok(false);
        }
        let result = if state.terminal != Some(credit) {
            Err("Fabric terminal acknowledgement does not match the emitted end".to_string())
        } else {
            state
                .window
                .acknowledge(credit)
                .map(|_| {
                    let changed = !state.terminal_acknowledged;
                    state.terminal_acknowledged = true;
                    changed
                })
        };
        if result.is_err() {
            state.failure = Some(StreamErrorCode::InvalidFrame);
            self.cancelled
                .send_replace(state.failure);
        }
        drop(state);
        if !matches!(result, Ok(false)) {
            self.changed.notify_one();
        }
        result
    }

    pub fn sent(&self) -> Result<Credit, StreamErrorCode> {
        let state = self
            .state
            .lock()
            .map_err(|_| StreamErrorCode::Unavailable)?;
        if let Some(error) = state.failure {
            return Err(error);
        }
        Ok(state.window.sent())
    }
}

#[derive(Debug)]
struct PendingChunk {
    offset: u64,
    bytes: Bytes,
}

#[derive(Debug)]
struct ConsumedChunk {
    sequence: u64,
    offset: u64,
    length: usize,
    digest: [u8; 32],
}

#[derive(Debug)]
pub(crate) struct ReceiveWindow {
    window_bytes: usize,
    buffered_bytes: usize,
    consumed: Credit,
    pending: BTreeMap<u64, PendingChunk>,
    history: VecDeque<ConsumedChunk>,
    end: Option<Credit>,
}

impl ReceiveWindow {
    pub fn new(window_bytes: usize) -> Result<Self, String> {
        SendWindow::new(window_bytes)?;
        Ok(Self {
            window_bytes,
            buffered_bytes: 0,
            consumed: Credit {
                next_sequence: 0,
                consumed_bytes: 0,
            },
            pending: BTreeMap::new(),
            history: VecDeque::new(),
            end: None,
        })
    }

    pub fn accept(
        &mut self,
        sequence: u64,
        offset: u64,
        bytes: Bytes,
    ) -> Result<bool, String> {
        if bytes.is_empty() || bytes.len() > MAX_CHUNK_BYTES {
            return Err("Invalid Fabric stream chunk size".to_string());
        }
        if sequence < self.consumed.next_sequence {
            let duplicate = self
                .history
                .iter()
                .any(|previous| {
                    previous.sequence == sequence
                        && previous.offset == offset
                        && previous.length == bytes.len()
                        && previous.digest == <[u8; 32]>::from(Sha256::digest(&bytes))
                });
            return if duplicate {
                Ok(false)
            } else {
                Err("Unverifiable or conflicting consumed Fabric stream frame".to_string())
            };
        }
        if let Some(previous) = self.pending.get(&sequence) {
            return if previous.offset == offset && previous.bytes == bytes {
                Ok(false)
            } else {
                Err("Conflicting duplicate Fabric stream frame".to_string())
            };
        }
        let end_offset = offset
            .checked_add(bytes.len() as u64)
            .ok_or("Fabric stream byte count overflow")?;
        let maximum_offset = self
            .consumed
            .consumed_bytes
            .checked_add(self.window_bytes as u64)
            .ok_or("Fabric stream receive window overflow")?;
        if sequence - self.consumed.next_sequence >= MAX_IN_FLIGHT_FRAMES as u64
            || offset < self.consumed.consumed_bytes
            || end_offset > maximum_offset
            || self
                .buffered_bytes
                .saturating_add(bytes.len())
                > self.window_bytes
            || self.pending.len() == MAX_IN_FLIGHT_FRAMES
        {
            return Err("Fabric stream frame exceeds the available receive window".to_string());
        }
        if self
            .end
            .is_some_and(|end| sequence >= end.next_sequence || end_offset > end.consumed_bytes)
        {
            return Err("Fabric stream data exceeds its terminal boundary".to_string());
        }
        if sequence == self.consumed.next_sequence && offset != self.consumed.consumed_bytes {
            return Err("Fabric stream data has a byte offset gap".to_string());
        }
        for (previous_sequence, previous) in &self.pending {
            let previous_end = previous.offset + previous.bytes.len() as u64;
            if (*previous_sequence < sequence && previous_end > offset)
                || (*previous_sequence > sequence && end_offset > previous.offset)
                || (previous_sequence.checked_add(1) == Some(sequence) && previous_end != offset)
                || (sequence.checked_add(1) == Some(*previous_sequence) && end_offset != previous.offset)
            {
                return Err("Fabric stream frame offsets overlap or disagree with their sequence".to_string());
            }
        }
        self.buffered_bytes += bytes.len();
        self.pending
            .insert(sequence, PendingChunk { offset, bytes });
        Ok(true)
    }

    pub fn consume(&mut self) -> Result<Option<(Bytes, Credit)>, String> {
        let Some(chunk) = self
            .pending
            .get(&self.consumed.next_sequence)
        else {
            return Ok(None);
        };
        if chunk.offset != self.consumed.consumed_bytes {
            return Err("Fabric stream data has a byte offset gap".to_string());
        }
        let next = Credit {
            next_sequence: self
                .consumed
                .next_sequence
                .checked_add(1)
                .ok_or("Fabric stream sequence overflow")?,
            consumed_bytes: chunk
                .offset
                .checked_add(chunk.bytes.len() as u64)
                .ok_or("Fabric stream byte count overflow")?,
        };
        if self
            .end
            .is_some_and(|end| next.next_sequence == end.next_sequence && next.consumed_bytes != end.consumed_bytes)
        {
            return Err("Fabric stream final byte count does not match its data".to_string());
        }
        let chunk = self
            .pending
            .remove(&self.consumed.next_sequence)
            .ok_or("Missing Fabric stream frame")?;
        self.buffered_bytes -= chunk.bytes.len();
        self.history
            .push_back(ConsumedChunk {
                sequence: self.consumed.next_sequence,
                offset: chunk.offset,
                length: chunk.bytes.len(),
                digest: Sha256::digest(&chunk.bytes).into(),
            });
        if self.history.len() > MAX_IN_FLIGHT_FRAMES {
            self.history.pop_front();
        }
        self.consumed = next;
        Ok(Some((chunk.bytes, next)))
    }

    pub fn finish(
        &mut self,
        end: Credit,
    ) -> Result<bool, String> {
        if let Some(previous) = self.end {
            return if previous == end {
                Ok(self.is_finished())
            } else {
                Err("Conflicting Fabric stream terminal frame".to_string())
            };
        }
        if end.next_sequence < self.consumed.next_sequence
            || end
                .next_sequence
                .saturating_sub(self.consumed.next_sequence)
                > MAX_IN_FLIGHT_FRAMES as u64
            || end.consumed_bytes < self.consumed.consumed_bytes
            || end
                .consumed_bytes
                .saturating_sub(self.consumed.consumed_bytes)
                > self.window_bytes as u64
            || (end.next_sequence == self.consumed.next_sequence && end.consumed_bytes != self.consumed.consumed_bytes)
            || self
                .pending
                .iter()
                .any(|(sequence, chunk)| {
                    *sequence >= end.next_sequence || chunk.offset + chunk.bytes.len() as u64 > end.consumed_bytes
                })
        {
            return Err("Invalid Fabric stream terminal boundary".to_string());
        }
        self.end = Some(end);
        Ok(self.is_finished())
    }

    pub fn is_finished(&self) -> bool {
        self.end == Some(self.consumed) && self.pending.is_empty()
    }

    pub fn consumed(&self) -> Credit {
        self.consumed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_progress_timeout_ends_waits_for_a_silent_peer_before_the_deadline() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3600);
        let credit = SendCredit::new(MAX_CHUNK_BYTES).unwrap();
        credit.set_progress_timeout(Duration::from_millis(200));
        credit
            .reserve(MAX_CHUNK_BYTES, deadline)
            .await
            .unwrap();
        let started = std::time::Instant::now();

        assert_eq!(
            credit
                .reserve(1, deadline)
                .await,
            Err(StreamErrorCode::DeadlineExceeded)
        );
        assert_eq!(
            credit
                .wait_consumed(deadline)
                .await,
            Err(StreamErrorCode::DeadlineExceeded)
        );
        assert!(started.elapsed() < Duration::from_secs(2), "took {:?}", started.elapsed());
    }

    #[tokio::test]
    async fn a_progress_timeout_does_not_bound_a_send_with_nothing_outstanding() {
        let credit = SendCredit::new(MAX_CHUNK_BYTES).unwrap();
        credit.set_progress_timeout(Duration::from_millis(1));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3600);

        assert_eq!(
            credit
                .wait_consumed(deadline)
                .await,
            Ok(())
        );
        assert!(
            credit
                .reserve(1, deadline)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn terminal_acknowledgement_requires_the_exact_sealed_boundary() {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        for bytes in [0, 5] {
            let credit = SendCredit::new(MAX_CHUNK_BYTES).unwrap();
            if bytes != 0 {
                credit
                    .reserve(bytes, deadline)
                    .await
                    .unwrap();
            }
            let terminal = credit.seal().unwrap();
            assert_eq!(
                credit
                    .reserve(1, deadline)
                    .await,
                Err(StreamErrorCode::InvalidFrame)
            );
            credit
                .acknowledge(terminal)
                .unwrap();
            let mut wait = Box::pin(credit.wait_consumed(deadline));
            assert!(futures::poll!(wait.as_mut()).is_pending());
            assert!(
                credit
                    .acknowledge_end(terminal)
                    .unwrap()
            );
            assert!(
                !credit
                    .acknowledge_end(terminal)
                    .unwrap()
            );
            assert_eq!(wait.await, Ok(()));
        }
        for sealed in [false, true] {
            let credit = SendCredit::new(MAX_CHUNK_BYTES).unwrap();
            credit
                .reserve(5, deadline)
                .await
                .unwrap();
            if sealed {
                credit.seal().unwrap();
            }
            assert!(
                credit
                    .acknowledge_end(Credit {
                        next_sequence: 1,
                        consumed_bytes: 4
                    })
                    .is_err()
            );
            assert_eq!(
                credit
                    .wait_consumed(deadline)
                    .await,
                Err(StreamErrorCode::InvalidFrame)
            );
        }
    }

    #[tokio::test]
    async fn sender_waits_for_consumption_and_wakes_for_credit_or_cancellation() {
        use futures::FutureExt;
        use std::time::Duration;

        let window = SendCredit::new(MAX_CHUNK_BYTES).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        assert_eq!(
            window
                .reserve(MAX_CHUNK_BYTES, deadline)
                .await
                .unwrap(),
            (0, 0)
        );
        let mut pending = Box::pin(window.reserve(1, deadline));
        assert!(
            pending
                .as_mut()
                .now_or_never()
                .is_none()
        );
        assert!(
            window
                .acknowledge(Credit {
                    next_sequence: 1,
                    consumed_bytes: MAX_CHUNK_BYTES as u64
                })
                .unwrap()
        );
        assert_eq!(pending.await.unwrap(), (1, MAX_CHUNK_BYTES as u64));
        assert_eq!(
            window
                .reserve(MAX_CHUNK_BYTES - 1, deadline)
                .await
                .unwrap(),
            (2, MAX_CHUNK_BYTES as u64 + 1)
        );
        let mut pending = Box::pin(window.reserve(1, deadline));
        assert!(
            pending
                .as_mut()
                .now_or_never()
                .is_none()
        );
        window.cancel(StreamErrorCode::Cancelled);
        assert_eq!(pending.await.unwrap_err(), StreamErrorCode::Cancelled);
        assert_eq!(window.sent().unwrap_err(), StreamErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn sender_deadlines_and_invalid_credits_never_authorize_more_bytes() {
        use std::time::Duration;

        let window = SendCredit::new(MAX_CHUNK_BYTES).unwrap();
        assert_eq!(
            window
                .reserve(1, tokio::time::Instant::now())
                .await
                .unwrap_err(),
            StreamErrorCode::DeadlineExceeded
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        assert_eq!(
            window
                .reserve(MAX_CHUNK_BYTES, deadline)
                .await
                .unwrap(),
            (0, 0)
        );
        assert!(
            window
                .acknowledge(Credit {
                    next_sequence: 99,
                    consumed_bytes: u64::MAX
                })
                .is_err()
        );
        assert_eq!(
            window
                .reserve(1, deadline)
                .await
                .unwrap_err(),
            StreamErrorCode::InvalidFrame
        );
        assert!(
            !window
                .acknowledge(Credit {
                    next_sequence: 1,
                    consumed_bytes: MAX_CHUNK_BYTES as u64
                })
                .unwrap()
        );
    }

    #[test]
    fn receive_reorders_bounded_chunks_and_credits_only_consumed_bytes() {
        let mut receive = ReceiveWindow::new(MAX_CHUNK_BYTES).unwrap();
        assert!(
            receive
                .accept(1, 3, Bytes::from_static(b"two"))
                .unwrap()
        );
        assert!(
            receive
                .consume()
                .unwrap()
                .is_none()
        );
        assert_eq!(
            receive.consumed(),
            Credit {
                next_sequence: 0,
                consumed_bytes: 0
            }
        );
        assert!(
            !receive
                .finish(Credit {
                    next_sequence: 2,
                    consumed_bytes: 6
                })
                .unwrap()
        );
        assert!(
            receive
                .accept(0, 0, Bytes::from_static(b"one"))
                .unwrap()
        );
        assert_eq!(
            receive.consume().unwrap(),
            Some((
                Bytes::from_static(b"one"),
                Credit {
                    next_sequence: 1,
                    consumed_bytes: 3
                }
            ))
        );
        assert!(!receive.is_finished());
        assert_eq!(
            receive.consume().unwrap(),
            Some((
                Bytes::from_static(b"two"),
                Credit {
                    next_sequence: 2,
                    consumed_bytes: 6
                }
            ))
        );
        assert!(receive.is_finished());
        assert!(
            receive
                .consume()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn receive_suppresses_duplicates_without_releasing_extra_credit() {
        let mut receive = ReceiveWindow::new(MAX_CHUNK_BYTES).unwrap();
        let bytes = Bytes::from_static(b"unchanged");
        assert!(
            receive
                .accept(0, 0, bytes.clone())
                .unwrap()
        );
        assert!(
            !receive
                .accept(0, 0, bytes.clone())
                .unwrap()
        );
        assert!(
            receive
                .accept(0, 0, Bytes::from_static(b"different"))
                .is_err()
        );
        let (_, credit) = receive
            .consume()
            .unwrap()
            .unwrap();
        assert!(
            !receive
                .accept(0, 0, bytes)
                .unwrap()
        );
        assert!(
            receive
                .accept(0, 0, Bytes::from_static(b"different"))
                .is_err()
        );
        assert_eq!(receive.consumed(), credit);
        assert!(
            receive
                .consume()
                .unwrap()
                .is_none()
        );
        assert!(
            receive
                .finish(credit)
                .unwrap()
        );
        assert!(
            receive
                .finish(credit)
                .unwrap()
        );
        assert!(
            receive
                .accept(1, credit.consumed_bytes, Bytes::from_static(b"late"))
                .is_err()
        );
    }

    #[test]
    fn receive_rejects_overlaps_gaps_uncredited_data_and_false_completion() {
        let mut receive = ReceiveWindow::new(MAX_CHUNK_BYTES).unwrap();
        assert!(
            receive
                .accept(0, 1, Bytes::from_static(b"gap"))
                .is_err()
        );
        assert!(
            receive
                .accept(MAX_IN_FLIGHT_FRAMES as u64, 0, Bytes::from_static(b"gap"))
                .is_err()
        );
        assert!(
            receive
                .accept(0, 0, Bytes::from(vec![0; MAX_CHUNK_BYTES]))
                .unwrap()
        );
        assert!(
            receive
                .accept(1, MAX_CHUNK_BYTES as u64, Bytes::from_static(b"uncredited"))
                .is_err()
        );
        assert!(
            receive
                .finish(Credit {
                    next_sequence: 0,
                    consumed_bytes: 0
                })
                .is_err()
        );
        receive
            .consume()
            .unwrap()
            .unwrap();
        assert!(
            receive
                .accept(2, MAX_CHUNK_BYTES as u64 + 3, Bytes::from_static(b"two"))
                .unwrap()
        );
        assert!(
            receive
                .accept(1, MAX_CHUNK_BYTES as u64, Bytes::from_static(b"overlap"))
                .is_err()
        );
        assert!(
            receive
                .accept(1, MAX_CHUNK_BYTES as u64, Bytes::from_static(b"one"))
                .unwrap()
        );
        assert!(
            !receive
                .finish(Credit {
                    next_sequence: 3,
                    consumed_bytes: MAX_CHUNK_BYTES as u64 + 7
                })
                .unwrap()
        );
        receive
            .consume()
            .unwrap()
            .unwrap();
        assert!(receive.consume().is_err());
        assert!(!receive.is_finished());
    }

    #[test]
    fn byte_credits_bound_send_and_only_release_consumed_frames() {
        let mut window = SendWindow::new(MAX_CHUNK_BYTES * 2).unwrap();
        assert_eq!(
            window
                .reserve(MAX_CHUNK_BYTES)
                .unwrap(),
            Some((0, 0))
        );
        let first = window.sent();
        assert_eq!(
            window
                .reserve(MAX_CHUNK_BYTES)
                .unwrap(),
            Some((1, MAX_CHUNK_BYTES as u64))
        );
        assert_eq!(window.reserve(1).unwrap(), None);
        assert!(
            window
                .acknowledge(first)
                .unwrap()
        );
        assert_eq!(
            window
                .reserve(MAX_CHUNK_BYTES)
                .unwrap(),
            Some((2, (MAX_CHUNK_BYTES * 2) as u64))
        );
        assert!(
            !window
                .acknowledge(first)
                .unwrap()
        );
        assert_eq!(window.reserve(1).unwrap(), None);
        assert!(
            window
                .acknowledge(window.sent())
                .unwrap()
        );
        assert!(
            window
                .reserve(MAX_CHUNK_BYTES)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn forged_partial_or_future_credits_do_not_expand_the_window() {
        let mut window = SendWindow::new(MAX_CHUNK_BYTES).unwrap();
        window
            .reserve(MAX_CHUNK_BYTES)
            .unwrap()
            .unwrap();
        for credit in [
            Credit {
                next_sequence: 1,
                consumed_bytes: 1,
            },
            Credit {
                next_sequence: 2,
                consumed_bytes: MAX_CHUNK_BYTES as u64,
            },
            Credit {
                next_sequence: 1,
                consumed_bytes: MAX_CHUNK_BYTES as u64 + 1,
            },
            Credit {
                next_sequence: u64::MAX,
                consumed_bytes: u64::MAX,
            },
        ] {
            assert!(
                window
                    .acknowledge(credit)
                    .is_err()
            );
            assert_eq!(window.reserve(1).unwrap(), None);
        }
    }

    #[test]
    fn tiny_frames_and_invalid_limits_cannot_create_unbounded_bookkeeping() {
        assert!(SendWindow::new(MAX_CHUNK_BYTES - 1).is_err());
        assert!(SendWindow::new(MAX_WINDOW_BYTES + 1).is_err());
        let mut window = SendWindow::new(MAX_WINDOW_BYTES).unwrap();
        for sequence in 0..MAX_IN_FLIGHT_FRAMES {
            assert_eq!(window.reserve(1).unwrap(), Some((sequence as u64, sequence as u64)));
        }
        assert_eq!(window.reserve(1).unwrap(), None);
        assert!(window.reserve(0).is_err());
        assert!(
            window
                .reserve(MAX_CHUNK_BYTES + 1)
                .is_err()
        );
        assert!(
            window
                .acknowledge(window.sent())
                .unwrap()
        );
        assert!(
            window
                .reserve(1)
                .unwrap()
                .is_some()
        );
    }
}
