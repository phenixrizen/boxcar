// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The hook a worker thread calls at its start. The VMM sets it once, before
//! it spawns anything (`boxcar_vmm::hardening::seccomp::set_mode`), to a
//! function that confines the calling thread by its name: the role's
//! seccomp filter, on that thread alone. A crate that spawns a worker (the
//! net stack, the virtio-fs device, the vsock device, the audit writer)
//! calls [`at_thread_start`] as the first thing its thread does and knows
//! nothing else of the policy; a process that set no hook (a client command,
//! a test) is left as it is.

use std::sync::OnceLock;

/// What the VMM set: given the thread's name, confines the calling thread.
static HOOK: OnceLock<fn(&str)> = OnceLock::new();

/// Sets the hook, once; a second call changes nothing and says so.
pub fn set_hook(hook: fn(&str)) -> bool {
    HOOK.set(hook).is_ok()
}

/// Called by a worker thread as its first statement: runs the hook, if
/// one is set, with the thread's name (nothing for an unnamed thread).
pub fn at_thread_start() {
    if let Some(hook) = HOOK.get() {
        if let Some(name) = std::thread::current().name() {
            hook(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());

    fn record(name: &str) {
        SEEN.lock().unwrap().push(name.to_owned());
    }

    /// The hook sees each named thread's name once, at its start; an
    /// unnamed thread passes nothing; a second hook is refused.
    #[test]
    fn the_hook_runs_with_the_threads_name() {
        assert!(set_hook(record));
        assert!(!set_hook(record));
        std::thread::Builder::new()
            .name("fs-root-q1".into())
            .spawn(at_thread_start)
            .unwrap()
            .join()
            .unwrap();
        std::thread::spawn(at_thread_start).join().unwrap();
        assert_eq!(*SEEN.lock().unwrap(), ["fs-root-q1"]);
    }
}
