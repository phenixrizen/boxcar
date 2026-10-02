// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Live subscriptions to a session's log: the records already in the log
//! from a seq on, then the ones the writer makes, with nothing missed and
//! nothing repeated between the two.
//!
//! [`AuditSink::subscribe`] asks the writer thread, in band with the events
//! it is writing, to register a subscriber. Between two records the writer
//! flushes the current segment, registers the subscriber, and answers with
//! the seq it gives the next record, `S`. Every record the writer makes
//! after that answer is sent to the subscriber's queue; none before it is.
//! The [`Subscription`] reads the records below `S` from the log's files
//! (see [`LogReader`]), then drains the queue, which starts at `S`. No lock
//! is taken on the writer's path to make this true.
//!
//! The writer never waits for a subscriber. Each has a queue of
//! [`DEFAULT_QUEUE`] records (`Arc<Record>`s, shared between the
//! subscribers), filled with `try_send`: a subscriber whose queue is full is
//! dropped from the writer's list, with a flag that says why. The
//! subscription sees its queue end with that flag set, yields
//! [`Item::Lagged`] once with the seq it resumes from, and subscribes again
//! from that seq: a replay from the files, then the live stream once more.
//! Nothing is buffered beyond the queue, whatever the subscriber's speed.
//!
//! The writer applies the subscriber's [`Filter`] before it queues a record,
//! so a subscriber that wants little is not flooded; the replay applies the
//! same filter.
//!
//! When the writer closes, the queue ends without the flag and the
//! subscription ends after the last record. If the writer closed while the
//! subscriber was dropped for lag, the subscription still reads the rest of
//! the log from its files, up to the last record the writer made, before it
//! ends. A writer that failed ends the subscription with that failure as an
//! error; the records it yielded before may include ones the failed writer
//! then cut off the end of the log.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use boxcar_proto::Record;
use crossbeam_channel::Sender;

use crate::reader::{Filter, LogReader, Records};
use crate::sink::AuditSink;

/// How many records a subscriber's queue holds before the writer drops it
/// for being too slow.
pub const DEFAULT_QUEUE: usize = 16384;

/// What a [`Subscription`] yields.
#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    /// A record the filter takes, in seq order.
    Record(Arc<Record>),
    /// The subscriber fell too far behind and the writer dropped it. The
    /// records from `resume_seq` on follow, read back from the log and then
    /// live, so that none is missed; the ones before it were delivered.
    Lagged { resume_seq: u64 },
}

/// The outcome of [`Subscription::next_timeout`].
#[derive(Clone, Debug, PartialEq)]
pub enum Next {
    Item(Item),
    /// Nothing came in time.
    Idle,
    /// The writer closed and every record has been delivered.
    End,
}

/// What the writer answers a subscription request with.
pub(crate) struct SubscribeAck {
    /// The seq of the first record the subscriber is sent live.
    pub(crate) next_seq: u64,
    pub(crate) session_dir: PathBuf,
}

/// A request for the writer to register a subscriber. It travels in the
/// writer's channel, in order with the events.
pub(crate) struct SubscribeRequest {
    pub(crate) sender: SyncSender<Arc<Record>>,
    pub(crate) filter: Filter,
    /// Set by the writer when it drops the subscriber for a full queue.
    pub(crate) lagged: Arc<AtomicBool>,
    pub(crate) reply: Sender<SubscribeAck>,
}

/// The writer's subscribers.
#[derive(Default)]
pub(crate) struct Subscribers {
    list: Vec<Subscriber>,
}

struct Subscriber {
    sender: SyncSender<Arc<Record>>,
    filter: Filter,
    lagged: Arc<AtomicBool>,
}

impl Subscribers {
    /// Registers the requester, which gets every record published from now
    /// on.
    pub(crate) fn add(&mut self, request: SubscribeRequest) {
        self.list.push(Subscriber {
            sender: request.sender,
            filter: request.filter,
            lagged: request.lagged,
        });
    }

    /// Sends `record` to every subscriber whose filter takes it. Never
    /// waits: a subscriber with a full queue is dropped, flagged as lagged,
    /// and one that is gone is dropped.
    pub(crate) fn publish(&mut self, record: Record) {
        if self.list.is_empty() {
            return;
        }
        let record = Arc::new(record);
        self.list.retain(|subscriber| {
            if !subscriber.filter.matches(&record) {
                return true;
            }
            match subscriber.sender.try_send(Arc::clone(&record)) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    // Before the sender is dropped: the subscription reads
                    // the flag once it sees the queue end.
                    subscriber.lagged.store(true, Ordering::Release);
                    false
                }
                Err(TrySendError::Disconnected(_)) => false,
            }
        });
    }
}

/// A registered subscriber's end of the writer's answer.
pub(crate) struct Attached {
    pub(crate) ack: SubscribeAck,
    pub(crate) queue: Receiver<Arc<Record>>,
    pub(crate) lagged: Arc<AtomicBool>,
}

/// The writer is closed, or has failed, and took no subscriber.
#[derive(Debug)]
pub(crate) struct Closed;

/// The live end of a subscription.
struct Live {
    queue: Receiver<Arc<Record>>,
    lagged: Arc<AtomicBool>,
}

/// What follows a replay.
enum Then {
    Live(Live),
    /// The writer has ended: the replay is the rest of the log.
    End,
}

enum State {
    /// Reading records below `until` from the log's files.
    Replay {
        records: Records,
        until: u64,
        then: Then,
    },
    Live(Live),
    /// Dropped for lag and reported: subscribes again on the next call.
    Resubscribe,
    /// The writer has ended and everything is delivered, but the end is not
    /// reported yet.
    Finished,
    /// Over, and reported.
    Ended,
}

/// A stream of a session's audit records: see the [module docs](self).
///
/// It is read by one thread, which blocks in [`next`](Self::next) or
/// [`next_timeout`](Self::next_timeout). Dropping it unsubscribes.
pub struct Subscription {
    sink: AuditSink,
    filter: Filter,
    queue: usize,
    dir: PathBuf,
    /// The seq the log's next record had when this subscribed first: where
    /// replay ends and the live records begin.
    live_from: u64,
    /// The lowest seq not yet delivered or passed over: records below it
    /// are not delivered, which is how a subscription from the future
    /// skips the live records before its `from_seq`.
    next_wanted: u64,
    state: State,
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscription")
            .field("filter", &self.filter)
            .field("next_wanted", &self.next_wanted)
            .finish_non_exhaustive()
    }
}

impl AuditSink {
    /// Subscribes to the records with seq `from_seq` or more that pass
    /// `filter`: those already in the log, then the live ones. `from_seq`
    /// 0 is the same as 1, the start; one beyond the log's end waits for
    /// the live records from that seq on. Fails if the writer is closed or
    /// has failed.
    pub fn subscribe(&self, from_seq: u64, filter: Filter) -> io::Result<Subscription> {
        self.subscribe_with_queue(from_seq, filter, DEFAULT_QUEUE)
    }

    /// [`subscribe`](Self::subscribe) with a queue of `queue` records
    /// (at least 1) in place of [`DEFAULT_QUEUE`]: how far behind the
    /// subscriber may fall before the writer drops it.
    pub fn subscribe_with_queue(
        &self,
        from_seq: u64,
        filter: Filter,
        queue: usize,
    ) -> io::Result<Subscription> {
        if queue == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an audit subscription's queue must hold at least 1 record",
            ));
        }
        let attached = self
            .attach(&filter, queue)
            .map_err(|Closed| self.closed())?;
        let mut subscription = Subscription {
            sink: self.clone(),
            filter,
            queue,
            dir: PathBuf::new(),
            live_from: 0,
            next_wanted: from_seq.max(1),
            state: State::Ended,
        };
        subscription.live_from = attached.ack.next_seq;
        subscription.begin(attached)?;
        Ok(subscription)
    }

    /// The error for a writer that took no subscriber.
    fn closed(&self) -> io::Error {
        match self.failure() {
            Some(failure) => io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("the audit log writer failed: {failure}"),
            ),
            None => io::Error::new(io::ErrorKind::BrokenPipe, "the audit log writer is closed"),
        }
    }
}

impl Subscription {
    /// The seq the log's next record had when this subscribed: the records
    /// below it come from the log's files, the ones from it on are live.
    /// (After a lag, the same holds again from the seq it resumed at; this
    /// stays what it was first.)
    pub fn next_seq(&self) -> u64 {
        self.live_from
    }

    /// The next item, waiting for it. `None` once the writer has closed and
    /// every record has been delivered. An error is a failed read of the
    /// log, a record that is not one, or a failed writer; the subscription
    /// is over after it.
    #[allow(clippy::should_implement_trait)] // it can fail, and may not be an `Iterator`
    pub fn next(&mut self) -> io::Result<Option<Item>> {
        loop {
            match self.advance(None)? {
                Next::Item(item) => return Ok(Some(item)),
                Next::End => return Ok(None),
                // No timeout was asked for.
                Next::Idle => {}
            }
        }
    }

    /// [`next`](Self::next), waiting at most `timeout` for a live record:
    /// [`Next::Idle`] when none comes. Reading the log back is not part of
    /// the wait.
    pub fn next_timeout(&mut self, timeout: Duration) -> io::Result<Next> {
        self.advance(Some(timeout))
    }

    /// Starts from the writer's answer: replay what the log holds below
    /// the answer's seq (and from `next_wanted`), then the live queue.
    fn begin(&mut self, attached: Attached) -> io::Result<()> {
        let Attached { ack, queue, lagged } = attached;
        self.dir = ack.session_dir;
        let live = Live { queue, lagged };
        self.state = if self.next_wanted >= ack.next_seq {
            State::Live(live)
        } else {
            let records = LogReader::open(&self.dir)?.records_from(self.next_wanted);
            State::Replay {
                records,
                until: ack.next_seq,
                then: Then::Live(live),
            }
        };
        Ok(())
    }

    /// After a lag: subscribes again from `next_wanted`. A writer that has
    /// closed in the meantime has written everything it will; the rest of
    /// the log is read from its files.
    fn resubscribe(&mut self) -> io::Result<()> {
        match self.sink.attach(&self.filter, self.queue) {
            Ok(attached) => self.begin(attached),
            Err(Closed) => {
                // The writer is done, so this is final.
                let until = self.sink.next_seq();
                if self.next_wanted >= until {
                    self.state = State::Finished;
                    return Ok(());
                }
                let records = LogReader::open(&self.dir)?.records_from(self.next_wanted);
                self.state = State::Replay {
                    records,
                    until,
                    then: Then::End,
                };
                Ok(())
            }
        }
    }

    fn advance(&mut self, wait: Option<Duration>) -> io::Result<Next> {
        loop {
            match std::mem::replace(&mut self.state, State::Ended) {
                State::Ended => return Ok(Next::End),
                State::Finished => return self.ended(),
                State::Resubscribe => self.resubscribe()?,
                State::Replay {
                    mut records,
                    until,
                    then,
                } => {
                    let record = match records.next() {
                        Some(Ok(record)) if record.seq < until => record,
                        // The end of the replay: its last record, or the
                        // end of the log.
                        reached => {
                            if let Some(Err(error)) = reached {
                                return Err(error);
                            }
                            self.state = match then {
                                Then::Live(live) if self.next_wanted >= until => State::Live(live),
                                Then::Live(_) => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        format!(
                                            "the audit log ends before seq {}, which the \
                                             writer had written when it was subscribed",
                                            self.next_wanted
                                        ),
                                    ))
                                }
                                // The writer failed, perhaps: then the log
                                // was cut back, and what is there is all.
                                Then::End => State::Finished,
                            };
                            continue;
                        }
                    };
                    self.state = State::Replay {
                        records,
                        until,
                        then,
                    };
                    if record.seq < self.next_wanted {
                        continue;
                    }
                    self.next_wanted = record.seq + 1;
                    if self.filter.matches(&record) {
                        return Ok(Next::Item(Item::Record(Arc::new(record))));
                    }
                }
                State::Live(live) => {
                    let received = match wait {
                        None => live
                            .queue
                            .recv()
                            .map_err(|_| RecvTimeoutError::Disconnected),
                        Some(timeout) => live.queue.recv_timeout(timeout),
                    };
                    match received {
                        Ok(record) => {
                            self.state = State::Live(live);
                            if record.seq >= self.next_wanted {
                                self.next_wanted = record.seq + 1;
                                return Ok(Next::Item(Item::Record(record)));
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            self.state = State::Live(live);
                            return Ok(Next::Idle);
                        }
                        Err(RecvTimeoutError::Disconnected) => {
                            if live.lagged.load(Ordering::Acquire) {
                                self.state = State::Resubscribe;
                                return Ok(Next::Item(Item::Lagged {
                                    resume_seq: self.next_wanted,
                                }));
                            }
                            return self.ended();
                        }
                    }
                }
            }
        }
    }

    /// Reports the end: clean, or the writer's failure.
    fn ended(&mut self) -> io::Result<Next> {
        self.state = State::Ended;
        match self.sink.failure() {
            Some(failure) => Err(io::Error::other(format!(
                "the audit log writer failed: {failure}"
            ))),
            None => Ok(Next::End),
        }
    }
}
