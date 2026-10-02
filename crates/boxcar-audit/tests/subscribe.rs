// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Live audit subscriptions, on real files in a temporary directory: replay
//! from the log and then the live stream with nothing missed or repeated
//! between them, recovery of a subscriber the writer dropped for being too
//! slow, filters, and the end of the stream when the writer closes.

use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::thread;
use std::time::Duration;

use boxcar_audit::{
    spawn, AuditSink, Filter, Item, Next, Priority, Submission, Subscription, WriterConfig,
    WriterHandle,
};
use boxcar_proto::{Attrib, FsIo, NetDrop, OpResult, Payload, Record, Ring, SessionId, Subject};
use tempfile::TempDir;

/// How long a test waits for the next item.
const LIMIT: Duration = Duration::from_secs(20);

/// A writer that makes no checkpoint of its own before it closes, so that
/// the seqs in a test are the events' own.
fn quiet_writer(dir: &Path) -> (AuditSink, WriterHandle) {
    let mut cfg = WriterConfig::new(dir, SessionId::new());
    cfg.checkpoint_every = 1_000_000;
    cfg.checkpoint_interval = Duration::from_secs(3600);
    spawn(cfg).unwrap()
}

fn subject(pid: u32) -> Option<Subject> {
    Some(Subject {
        pid,
        uid: 1000,
        gid: 1000,
    })
}

/// An `fs.write` of `fh` = `n` by `pid`.
fn fs_event(n: u64, pid: u32) -> Submission {
    Submission {
        ring: Ring::Host,
        ts_guest_ns: None,
        subject: subject(pid),
        payload: Payload::FsWrite(FsIo {
            mount: "workspace".into(),
            path: format!("/file-{n:06}.txt"),
            fh: n,
            offset: 0,
            len: 1,
            result: OpResult::ok(),
            attrib: Attrib::Caller,
        }),
        span: None,
        priority: Priority::Normal,
    }
}

fn event(n: u64) -> Submission {
    fs_event(n, 42)
}

/// A `net.drop` of `count` = `n` by `pid`.
fn net_event(n: u64, pid: u32) -> Submission {
    Submission {
        payload: Payload::NetDrop(NetDrop {
            reason: "ipv6".into(),
            count: n,
        }),
        ..fs_event(n, pid)
    }
}

/// The next item, waiting at most [`LIMIT`] for it. `None` is the end.
fn next(sub: &mut Subscription) -> Option<Item> {
    match sub.next_timeout(LIMIT).unwrap() {
        Next::Item(item) => Some(item),
        Next::End => None,
        Next::Idle => panic!("nothing in {LIMIT:?}"),
    }
}

/// Everything up to the end of the stream.
fn drain(sub: &mut Subscription) -> Vec<Item> {
    std::iter::from_fn(|| next(sub)).collect()
}

/// Items up to and including the record with seq `last`.
fn collect_until(sub: &mut Subscription, last: u64) -> Vec<Item> {
    let mut items = Vec::new();
    loop {
        let item = next(sub).expect("the stream ended early");
        let done = matches!(&item, Item::Record(record) if record.seq == last);
        items.push(item);
        if done {
            return items;
        }
    }
}

/// The seqs of the records among `items`.
fn seqs(items: &[Item]) -> Vec<u64> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::Record(record) => Some(record.seq),
            Item::Lagged { .. } => None,
        })
        .collect()
}

/// The next record, which must be one.
fn next_record(sub: &mut Subscription) -> std::sync::Arc<Record> {
    match next(sub) {
        Some(Item::Record(record)) => record,
        other => panic!("expected a record, got {other:?}"),
    }
}

/// Waits until the writer has written everything emitted so far, by a
/// round trip through its channel.
fn barrier(sink: &AuditSink) {
    drop(sink.subscribe(u64::MAX, Filter::default()).unwrap());
}

#[test]
fn replay_then_live_without_gaps() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = quiet_writer(tmp.path());
    for n in 0..100 {
        sink.emit(event(n)).unwrap();
    }
    let mut sub = sink.subscribe(1, Filter::default()).unwrap();
    assert_eq!(sub.next_seq(), 101, "the first live seq");
    let producer = thread::spawn({
        let sink = sink.clone();
        move || {
            for n in 100..200 {
                sink.emit(event(n)).unwrap();
            }
        }
    });
    let mut got = Vec::new();
    while got.len() < 200 {
        got.push(next_record(&mut sub));
    }
    producer.join().unwrap();
    let want: Vec<u64> = (1..=200).collect();
    assert_eq!(got.iter().map(|r| r.seq).collect::<Vec<_>>(), want);
    // The events, in the order they were emitted, each once.
    let fhs: Vec<u64> = got.iter().map(|r| r.data["fh"].as_u64().unwrap()).collect();
    assert_eq!(fhs, (0..200).collect::<Vec<u64>>());
    writer.close().unwrap();
}

#[test]
fn replay_starts_at_from_seq() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = quiet_writer(tmp.path());
    for n in 0..20 {
        sink.emit(event(n)).unwrap();
    }
    // 0 means from the start, like 1.
    let mut all = sink.subscribe(0, Filter::default()).unwrap();
    assert_eq!(next_record(&mut all).seq, 1);
    let mut tail = sink.subscribe(15, Filter::default()).unwrap();
    for want in 15..=20 {
        assert_eq!(next_record(&mut tail).seq, want);
    }
    sink.emit(event(20)).unwrap();
    assert_eq!(next_record(&mut tail).seq, 21);
    writer.close().unwrap();
}

#[test]
fn a_lagged_subscriber_gets_resume_seq_and_recovers() {
    const EVENTS: u64 = 20_000;
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = quiet_writer(tmp.path());
    let mut sub = sink.subscribe(1, Filter::default()).unwrap();
    // The subscriber reads nothing while the writer writes far more than
    // its queue holds (16384): the writer drops it, and never waits.
    for n in 0..EVENTS {
        sink.emit(event(n)).unwrap();
    }
    barrier(&sink);

    // What was queued comes first, then the report, then the rest from the
    // log, then the live stream again.
    let items = collect_until(&mut sub, EVENTS);
    let lagged: Vec<(usize, u64)> = items
        .iter()
        .enumerate()
        .filter_map(|(at, item)| match item {
            Item::Lagged { resume_seq } => Some((at, *resume_seq)),
            Item::Record(_) => None,
        })
        .collect();
    assert_eq!(lagged, [(16_384, 16_385)], "one report, at the queue's end");
    assert_eq!(seqs(&items), (1..=EVENTS).collect::<Vec<_>>());

    // Recovered: it follows the live stream.
    sink.emit(event(EVENTS)).unwrap();
    assert_eq!(next_record(&mut sub).seq, EVENTS + 1);
    writer.close().unwrap();
}

#[test]
fn a_subscriber_that_lags_over_and_over_still_sees_every_record_once() {
    const EVENTS: u64 = 2_000;
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = quiet_writer(tmp.path());
    let mut sub = sink.subscribe_with_queue(1, Filter::default(), 4).unwrap();
    let producer = thread::spawn({
        let sink = sink.clone();
        move || {
            // Faster than the subscriber reads, even while it replays.
            for n in 0..EVENTS {
                sink.emit(event(n)).unwrap();
                if n % 10 == 9 {
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
    });
    let mut items = Vec::new();
    loop {
        let item = next(&mut sub).expect("the stream ended early");
        let done = matches!(&item, Item::Record(record) if record.seq == EVENTS);
        items.push(item);
        if done {
            break;
        }
        if items.len() % 4 == 0 {
            // Slower than the writer, so that the queue overflows again and
            // again.
            thread::sleep(Duration::from_millis(1));
        }
    }
    producer.join().unwrap();
    assert_eq!(seqs(&items), (1..=EVENTS).collect::<Vec<_>>());
    let laggeds = items
        .iter()
        .filter(|item| matches!(item, Item::Lagged { .. }))
        .count();
    assert!(laggeds > 1, "only {laggeds} lag reports");
    // Each report names the seq the next record has.
    for (at, item) in items.iter().enumerate() {
        if let Item::Lagged { resume_seq } = item {
            match &items[at + 1] {
                Item::Record(next) => assert_eq!(next.seq, *resume_seq),
                other => panic!("a report followed by {other:?}"),
            }
        }
    }
    writer.close().unwrap();
}

#[test]
fn filters_by_prefix_and_pid() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = quiet_writer(tmp.path());
    // Before the subscriptions: replayed. After: live.
    sink.emit(fs_event(1, 10)).unwrap(); // seq 1
    sink.emit(net_event(2, 10)).unwrap(); // 2
    sink.emit(fs_event(3, 20)).unwrap(); // 3
    sink.emit(net_event(4, 20)).unwrap(); // 4
    let kinds = |prefixes: &[&str]| Filter {
        kinds: prefixes.iter().map(|p| (*p).to_owned()).collect(),
        ..Filter::default()
    };
    let mut net = sink.subscribe(1, kinds(&["net."])).unwrap();
    let mut pid20 = sink
        .subscribe(
            1,
            Filter {
                pid: Some(20),
                ..Filter::default()
            },
        )
        .unwrap();
    let mut net_pid10 = sink
        .subscribe(
            1,
            Filter {
                pid: Some(10),
                ..kinds(&["net.", "vsock."])
            },
        )
        .unwrap();
    let mut exact = sink.subscribe(1, kinds(&["fs.write"])).unwrap();
    sink.emit(net_event(5, 10)).unwrap(); // 5
    sink.emit(fs_event(6, 20)).unwrap(); // 6
    sink.emit(net_event(7, 30)).unwrap(); // 7
    sink.emit(fs_event(8, 10)).unwrap(); // 8
    let stats = writer.close().unwrap();
    assert_eq!(stats.last_seq, 9, "the closing checkpoint is seq 9");

    assert_eq!(seqs(&drain(&mut net)), [2, 4, 5, 7]);
    assert_eq!(seqs(&drain(&mut pid20)), [3, 4, 6]);
    assert_eq!(seqs(&drain(&mut net_pid10)), [2, 5]);
    assert_eq!(seqs(&drain(&mut exact)), [1, 3, 6, 8]);
}

#[test]
fn a_filtered_subscriber_that_lags_resumes_with_its_filter() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = quiet_writer(tmp.path());
    let only_net = Filter {
        kinds: vec!["net.".into()],
        ..Filter::default()
    };
    let mut sub = sink.subscribe_with_queue(1, only_net, 2).unwrap();
    // Every third event matches; the subscriber reads nothing until the
    // writer has dropped it.
    for n in 0..60u64 {
        sink.emit(if n % 3 == 0 {
            net_event(n, 7)
        } else {
            fs_event(n, 7)
        })
        .unwrap();
    }
    barrier(&sink);
    let items = collect_until(&mut sub, 58);
    let want: Vec<u64> = (1..=60).filter(|seq| (seq - 1) % 3 == 0).collect();
    assert_eq!(seqs(&items), want);
    assert!(items.iter().any(|item| matches!(item, Item::Lagged { .. })));
    writer.close().unwrap();
}

#[test]
fn replay_spans_the_segments_of_a_rotated_log() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = WriterConfig::new(tmp.path(), SessionId::new());
    cfg.checkpoint_interval = Duration::from_secs(3600);
    cfg.segment_max_bytes = 3000;
    let (sink, writer) = spawn(cfg).unwrap();
    for n in 0..100 {
        sink.emit(event(n)).unwrap();
    }
    barrier(&sink);
    let last = sink.next_seq() - 1;
    assert!(last > 100, "the seals add checkpoints: {last}");
    let segments = std::fs::read_dir(writer.session_dir())
        .unwrap()
        .filter(|e| {
            let name = e.as_ref().unwrap().file_name();
            name.to_str().unwrap().starts_with("events.")
        })
        .count();
    assert!(segments > 3, "only {segments} segments");

    let mut all = sink.subscribe(1, Filter::default()).unwrap();
    assert_eq!(
        seqs(&collect_until(&mut all, last)),
        (1..=last).collect::<Vec<_>>()
    );
    let mut from_middle = sink.subscribe(60, Filter::default()).unwrap();
    assert_eq!(
        seqs(&collect_until(&mut from_middle, last)),
        (60..=last).collect::<Vec<_>>()
    );
    writer.close().unwrap();
}

#[test]
fn subscribe_from_the_future_waits_for_live() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = quiet_writer(tmp.path());
    for n in 0..10 {
        sink.emit(event(n)).unwrap();
    }
    let mut sub = sink.subscribe(15, Filter::default()).unwrap();
    assert_eq!(sub.next_seq(), 11, "the log's end when it subscribed");
    // Nothing yet: the log ends at seq 10.
    assert!(matches!(
        sub.next_timeout(Duration::from_millis(100)).unwrap(),
        Next::Idle
    ));
    for n in 10..20 {
        sink.emit(event(n)).unwrap();
    }
    // Seqs 11 to 14 are live too, and not delivered.
    let got: Vec<u64> = (0..6).map(|_| next_record(&mut sub).seq).collect();
    assert_eq!(got, [15, 16, 17, 18, 19, 20]);
    writer.close().unwrap();
}

#[test]
fn subscription_ends_when_the_writer_closes() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = quiet_writer(tmp.path());
    let mut sub = sink.subscribe(1, Filter::default()).unwrap();
    for n in 0..5 {
        sink.emit(event(n)).unwrap();
    }
    let stats = writer.close().unwrap();
    // Every record, the closing checkpoint included, then the end.
    let items = drain(&mut sub);
    assert_eq!(seqs(&items), (1..=stats.last_seq).collect::<Vec<_>>());
    assert_eq!(stats.last_seq, 6);
    assert!(items.iter().all(|item| matches!(item, Item::Record(_))));
    // And stays ended.
    assert!(next(&mut sub).is_none());
}

#[test]
fn a_subscriber_dropped_for_lag_when_the_writer_closes_still_gets_the_tail() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = quiet_writer(tmp.path());
    let mut sub = sink.subscribe_with_queue(1, Filter::default(), 4).unwrap();
    for n in 0..50 {
        sink.emit(event(n)).unwrap();
    }
    // Closes with the subscriber far behind and dropped.
    let stats = writer.close().unwrap();
    let items = drain(&mut sub);
    assert_eq!(seqs(&items), (1..=stats.last_seq).collect::<Vec<_>>());
    assert_eq!(items[4], Item::Lagged { resume_seq: 5 });
}

#[test]
fn subscribing_to_a_closed_writer_is_refused() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = quiet_writer(tmp.path());
    writer.close().unwrap();
    let error = sink.subscribe(1, Filter::default()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe, "{error}");
}

#[test]
fn a_dropped_subscription_does_not_hold_the_writer_up() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = quiet_writer(tmp.path());
    let subs: Vec<Subscription> = (0..8)
        .map(|_| sink.subscribe(1, Filter::default()).unwrap())
        .collect();
    drop(subs);
    for n in 0..100 {
        sink.emit(event(n)).unwrap();
    }
    let stats = writer.close().unwrap();
    assert_eq!(stats.last_seq, 101);
}

#[test]
fn every_seq_is_delivered_once_to_each_of_several_subscribers() {
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = quiet_writer(tmp.path());
    let subs: Vec<Subscription> = (0..3)
        .map(|_| sink.subscribe(1, Filter::default()).unwrap())
        .collect();
    let readers: Vec<_> = subs
        .into_iter()
        .map(|mut sub| thread::spawn(move || seqs(&drain(&mut sub))))
        .collect();
    for n in 0..300 {
        sink.emit(event(n)).unwrap();
    }
    let stats = writer.close().unwrap();
    let want: BTreeSet<u64> = (1..=stats.last_seq).collect();
    for reader in readers {
        let got = reader.join().unwrap();
        assert_eq!(got.iter().copied().collect::<BTreeSet<_>>(), want);
        assert_eq!(got.len(), want.len());
    }
}

/// A replay that passes over many records without one to deliver (a filter
/// that few records match, over a long log) does not hold `next_timeout`
/// for its whole length: it returns `Idle` now and then, so that a caller
/// that also watches something else (a connection that is closing) gets to
/// look. `next`, which was not asked for a wait, reads straight through.
#[test]
fn a_long_filtered_replay_yields_idle_now_and_then() {
    const EVENTS: u64 = 5_000;
    let tmp = TempDir::new().unwrap();
    let (sink, writer) = quiet_writer(tmp.path());
    for n in 0..EVENTS {
        sink.emit(fs_event(n, 1)).unwrap();
    }
    sink.emit(net_event(EVENTS, 1)).unwrap(); // seq 5001
    barrier(&sink);
    let only_net = Filter {
        kinds: vec!["net.".into()],
        ..Filter::default()
    };

    let mut sub = sink.subscribe(1, only_net.clone()).unwrap();
    let mut idles = 0;
    let record = loop {
        match sub.next_timeout(LIMIT).unwrap() {
            Next::Idle => idles += 1,
            Next::Item(Item::Record(record)) => break record,
            other => panic!("{other:?}"),
        }
        assert!(idles < 100, "idle for ever");
    };
    assert_eq!(record.seq, EVENTS + 1);
    assert_eq!(
        idles,
        (EVENTS as usize) / boxcar_audit::REPLAY_YIELD,
        "one idle per {} records passed over",
        boxcar_audit::REPLAY_YIELD
    );

    // Without a wait, the replay is read through to the record.
    let mut plain = sink.subscribe(1, only_net).unwrap();
    match plain.next().unwrap() {
        Some(Item::Record(record)) => assert_eq!(record.seq, EVENTS + 1),
        other => panic!("{other:?}"),
    }
    writer.close().unwrap();
}
