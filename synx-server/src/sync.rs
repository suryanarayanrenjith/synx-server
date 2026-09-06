//! Locking that survives a panic.
//!
//! WHY THIS EXISTS.
//!
//! Rust's `Mutex` is poisoned by a panic. If a thread panics while holding the
//! lock, every later `lock()` returns `Err` forever - and the idiom everybody
//! writes, `lock().unwrap()`, turns that `Err` into another panic.
//!
//! That is a sensible default for a program where a panic means the protected
//! data might be half-updated and acting on it would be worse than stopping.
//! It is the wrong default here, and the difference is worth being precise
//! about, because "just unwrap it" was the shape of a genuine outage:
//!
//! This server's shared state is three plain tables - open rooms, live
//! sessions, per-address rate limiters. Every mutation is a single map
//! insert, remove or counter update. There is no multi-step invariant that a
//! panic can leave half-finished, so a poisoned lock here does not mean the
//! data is untrustworthy; it means something unrelated panicked once, at some
//! point, somewhere else.
//!
//! With `lock().unwrap()` the consequence of that one panic is total and
//! permanent. The room table is taken every time anybody lists rooms, joins
//! one, or opens one; the session table on every registration and every socket.
//! So a single panic in a single room task - the exact thing `room.rs` already
//! goes to the trouble of supervising and recovering from - poisons the tables
//! and every subsequent request panics on the way in. The process keeps
//! running, keeps passing its health check, and refuses everybody. That is a
//! far worse failure than the panic it came from, and it is silent.
//!
//! So the locks here recover: take the data back out of the poison and carry
//! on. The panic that caused it is not swallowed - whatever panicked has
//! already unwound and been logged by its supervisor - and this is not a
//! blanket "ignore errors" habit. It is the specific, considered answer for
//! three specific tables whose contents are still perfectly good.

use std::sync::{Mutex, MutexGuard};

/// `lock()` that recovers from poisoning instead of propagating it.
pub trait LockExt<T> {
    /// Take the lock, taking the data back out of a poisoned one.
    ///
    /// See the module note. Use this rather than `lock().unwrap()` for any
    /// state whose invariants are per-operation, which in this server is all
    /// of it.
    fn lock_safe(&self) -> MutexGuard<'_, T>;
}

impl<T> LockExt<T> for Mutex<T> {
    fn lock_safe(&self) -> MutexGuard<'_, T> {
        // `into_inner` on the poison error is the guard that was going to be
        // handed over anyway; the error is the flag, not a different value.
        self.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// The whole point: a panic while the lock is held must not take the lock
    /// away from everybody who comes after.
    #[test]
    fn a_poisoned_lock_is_still_usable() {
        let m = Arc::new(Mutex::new(vec![1u32, 2, 3]));

        let victim = m.clone();
        let died = std::thread::spawn(move || {
            let mut g = victim.lock_safe();
            g.push(4);
            panic!("something went wrong in here");
        })
        .join();
        assert!(died.is_err(), "the thread was supposed to panic");

        // The standard idiom would panic on this line, for as long as the
        // process lived.
        assert!(m.lock().is_err(), "the lock really is poisoned");

        let g = m.lock_safe();
        assert_eq!(*g, vec![1, 2, 3, 4], "the data survived, including the last write");
    }

    #[test]
    fn an_unpoisoned_lock_behaves_exactly_as_before() {
        let m = Mutex::new(7u32);
        *m.lock_safe() += 1;
        assert_eq!(*m.lock_safe(), 8);
    }
}
