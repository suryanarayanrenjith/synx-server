//! Rate limiting and per-address connection counters.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A token bucket.
///
/// `rate` tokens accrue per second up to `burst`; each admitted message costs
/// one. Empty means refused. There is no timer and no background task - the
/// bucket is refilled lazily from the clock the moment it is asked.
#[derive(Debug)]
pub struct Bucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: Instant,
}

impl Bucket {
    pub fn new(rate: f64, burst: f64) -> Bucket {
        Bucket { tokens: burst, rate, burst, last: Instant::now() }
    }

    /// Per second, allowing a second of traffic as the burst. Two seconds of
    /// burst would let a client bank enough to matter; half a second is tight
    /// enough that a legitimate hiccup trips it.
    pub fn per_second(rate: f64) -> Bucket {
        Bucket::new(rate, rate.max(4.0))
    }

    /// Take one token. False means the caller should drop the message.
    pub fn take(&mut self) -> bool {
        self.take_n(1.0)
    }

    pub fn take_n(&mut self, n: f64) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// How full the bucket is, for the diagnostics endpoint.
    pub fn level(&self) -> f64 {
        self.tokens
    }
}

/// How many connections each address currently has.
///
/// A `HashMap` rather than anything cleverer: the whole instance is capped at
/// under a hundred connections, so this map is tiny and is touched twice per
/// connection lifetime.
#[derive(Default)]
pub struct IpTable {
    live: HashMap<IpAddr, usize>,
    /// Registration attempts, so one address cannot mint sessions in a loop.
    register: HashMap<IpAddr, Bucket>,
    /// Every HTTP request, so an address cannot make the process spend its
    /// whole CPU budget answering a loop of `/wake`.
    http: HashMap<IpAddr, Bucket>,
    /// Connection ATTEMPTS, which is a different thing from connections held.
    ///
    /// Four players behind one router legitimately sit at the per-address cap
    /// all evening; that is not abuse and must not be punished. Opening
    /// sockets in a loop is, and it is the rate that tells them apart.
    connect: HashMap<IpAddr, Bucket>,
    /// Addresses that have tripped a limit often enough to be refused
    /// outright for a while, and when they were jailed.
    ///
    /// This is the difference between a limit and a defence. A token bucket
    /// alone still costs a lookup, a clock read and a response for every
    /// request in a flood; a jail turns the second minute of that flood into
    /// one comparison and a 429. It is deliberately short and automatic -
    /// there is no manual list to maintain and nothing to forget to remove.
    jail: HashMap<IpAddr, (Instant, u32)>,
    /// New connections across the whole process, so a distributed flood is
    /// bounded even when no single address trips its own limit.
    accepts: Option<Bucket>,
    total: usize,
}

/// How long an address stays jailed the first time, doubling with each repeat
/// up to an hour.
const JAIL_BASE_SECS: u64 = 30;
const JAIL_MAX_SECS: u64 = 3_600;

/// Why a request or a connection was refused, so the log and the client both
/// get a reason rather than a closed socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    ServerFull,
    TooManyFromAddress,
    TooFast,
    Jailed,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::ServerFull => "the grid is full",
            Refusal::TooManyFromAddress => "too many connections from this address",
            Refusal::TooFast => "too many requests; slow down",
            Refusal::Jailed => "this address is temporarily blocked",
        }
    }

    pub fn status(self) -> u16 {
        match self {
            Refusal::ServerFull => 503,
            Refusal::TooManyFromAddress => 429,
            Refusal::TooFast => 429,
            Refusal::Jailed => 429,
        }
    }
}

impl IpTable {
    /// Claim a slot for `ip`. The caller must call [`IpTable::release`] on
    /// every path out of the connection, including the error ones.
    pub fn admit(&mut self, ip: IpAddr, max_total: usize, max_per_ip: usize) -> Result<(), Refusal> {
        if self.total >= max_total {
            return Err(Refusal::ServerFull);
        }
        let n = self.live.entry(ip).or_insert(0);
        if *n >= max_per_ip {
            return Err(Refusal::TooManyFromAddress);
        }
        *n += 1;
        self.total += 1;
        Ok(())
    }

    pub fn release(&mut self, ip: IpAddr) {
        if let Some(n) = self.live.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.live.remove(&ip);
            }
        }
        self.total = self.total.saturating_sub(1);
    }

    /// May this address register another session right now?
    pub fn may_register(&mut self, ip: IpAddr, per_minute: u32) -> bool {
        let b = self
            .register
            .entry(ip)
            .or_insert_with(|| Bucket::new(per_minute as f64 / 60.0, per_minute as f64));
        if b.take() {
            true
        } else {
            self.punish(ip);
            false
        }
    }

    /// The gate every inbound HTTP request passes through.
    ///
    /// Order matters and is the whole point: the jail is checked before the
    /// bucket, because the jail is one hash lookup and the bucket is a clock
    /// read and an insert. Under a flood, the cheap test is the one that has
    /// to come first.
    pub fn may_request(&mut self, ip: IpAddr, per_second: f64) -> Result<(), Refusal> {
        if self.jailed(ip) {
            return Err(Refusal::Jailed);
        }
        let b = self
            .http
            .entry(ip)
            .or_insert_with(|| Bucket::new(per_second, (per_second * 2.0).max(8.0)));
        if b.take() {
            Ok(())
        } else {
            self.punish(ip);
            Err(Refusal::TooFast)
        }
    }

    /// Is this address currently jailed?
    ///
    /// The sentence doubles with each repeat and the entry is left in place
    /// once it has been served, so an address that comes back and offends
    /// again is jailed for longer rather than starting from thirty seconds
    /// every time. The sweep forgets entries that have been quiet for an hour.
    pub fn jailed(&self, ip: IpAddr) -> bool {
        let Some((at, strikes)) = self.jail.get(&ip) else { return false };
        let secs = (JAIL_BASE_SECS << (*strikes).min(7)).min(JAIL_MAX_SECS);
        at.elapsed().as_secs() < secs
    }

    /// This address tripped a limit.
    ///
    /// # Once per episode, not once per packet
    ///
    /// The obvious version counts every refusal, and it is badly wrong: a
    /// single burst of a hundred requests is one mistake, but it arrives as a
    /// hundred refusals, so an escalating sentence goes straight to its
    /// maximum. A tab left refreshing would earn an hour on its first outing.
    ///
    /// So the tier escalates once per SENTENCE. An address already serving one
    /// is left alone - it is already costing the server nothing but a hash
    /// lookup - and the tier only goes up if it comes back and offends again
    /// while its last sentence is still remembered.
    pub fn punish(&mut self, ip: IpAddr) {
        if self.jailed(ip) {
            return;
        }
        let tier = match self.jail.get(&ip) {
            Some((at, tier)) => {
                let served = Duration::from_secs((JAIL_BASE_SECS << (*tier).min(7)).min(JAIL_MAX_SECS));
                // Repeat offender, if the last sentence is still within
                // memory; otherwise it starts again from the bottom.
                if at.elapsed() < served + Duration::from_secs(600) {
                    tier.saturating_add(1)
                } else {
                    0
                }
            }
            None => 0,
        };
        self.jail.insert(ip, (Instant::now(), tier));
    }

    /// May this address try to open another socket right now?
    ///
    /// Separate from [`IpTable::admit`]: this meters attempts and is what can
    /// jail an address, while `admit` counts what is actually held open and
    /// only ever refuses.
    pub fn may_connect(&mut self, ip: IpAddr, per_second: f64) -> bool {
        if self.jailed(ip) {
            return false;
        }
        let b = self
            .connect
            .entry(ip)
            .or_insert_with(|| Bucket::new(per_second, (per_second * 3.0).max(6.0)));
        if b.take() {
            true
        } else {
            self.punish(ip);
            false
        }
    }

    /// The global accept gate: how many NEW connections the process will take
    /// per second, whoever they are from.
    ///
    /// The per-address cap stops one machine; this stops a thousand. A racing
    /// server that is doing its job accepts a handful of connections a second,
    /// so a ceiling well above that is invisible to players and is the
    /// difference between a botnet costing CPU and costing nothing.
    pub fn may_accept(&mut self, per_second: f64) -> bool {
        let b = self
            .accepts
            .get_or_insert_with(|| Bucket::new(per_second, (per_second * 3.0).max(12.0)));
        b.take()
    }

    /// Drop buckets that have refilled completely and jail entries that have
    /// been quiet for an hour, so an idle server does not carry a map entry
    /// for every address that ever asked.
    pub fn sweep(&mut self) {
        self.register.retain(|_, b| b.level() < b.burst - 0.001);
        self.http.retain(|_, b| b.level() < b.burst - 0.001);
        self.connect.retain(|_, b| b.level() < b.burst - 0.001);
        self.jail.retain(|_, (at, _)| at.elapsed() < Duration::from_secs(3_600));
    }

    /// How many addresses are currently jailed, for the diagnostics endpoint.
    pub fn jailed_count(&self) -> usize {
        self.jail.len()
    }

    pub fn total(&self) -> usize {
        self.total
    }

    pub fn addresses(&self) -> usize {
        self.live.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn a_bucket_admits_a_burst_and_then_refuses() {
        let mut b = Bucket::new(10.0, 10.0);
        for i in 0..10 {
            assert!(b.take(), "token {i} of the burst was refused");
        }
        assert!(!b.take(), "the eleventh token was admitted");
    }

    #[test]
    fn a_bucket_refills_over_time() {
        let mut b = Bucket::new(1000.0, 4.0);
        for _ in 0..4 {
            assert!(b.take());
        }
        assert!(!b.take());
        std::thread::sleep(std::time::Duration::from_millis(12));
        assert!(b.take(), "the bucket did not refill");
    }

    #[test]
    fn the_ip_table_caps_both_ways() {
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 7).into();
        let other: IpAddr = Ipv4Addr::new(203, 0, 113, 8).into();
        let mut t = IpTable::default();

        for _ in 0..3 {
            t.admit(ip, 10, 3).unwrap();
        }
        assert_eq!(t.admit(ip, 10, 3), Err(Refusal::TooManyFromAddress));
        // a different address is unaffected
        t.admit(other, 10, 3).unwrap();
        assert_eq!(t.total(), 4);

        // and the global cap bites regardless of who is asking
        assert_eq!(t.admit(other, 4, 3), Err(Refusal::ServerFull));

        for _ in 0..3 {
            t.release(ip);
        }
        assert_eq!(t.addresses(), 1, "the entry was not cleaned up");
        t.admit(ip, 10, 3).unwrap();
    }

    #[test]
    fn releasing_more_than_was_admitted_cannot_underflow() {
        let ip: IpAddr = Ipv4Addr::new(198, 51, 100, 1).into();
        let mut t = IpTable::default();
        t.admit(ip, 10, 3).unwrap();
        for _ in 0..5 {
            t.release(ip);
        }
        assert_eq!(t.total(), 0);
        t.admit(ip, 10, 3).unwrap();
    }

    /// A burst is one mistake however many requests it arrives as. Without
    /// this the first flood an address produces jails it for the maximum.
    #[test]
    fn a_burst_earns_one_sentence_not_a_hundred() {
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 200).into();
        let mut t = IpTable::default();
        for _ in 0..200 {
            let _ = t.may_request(ip, 4.0);
        }
        assert!(t.jailed(ip), "a flood was not jailed");
        // one sentence at the bottom of the ladder, not the top
        let (_, tier) = *t.jail.get(&ip).unwrap();
        assert_eq!(tier, 0, "a single burst escalated to tier {tier}");
    }

    #[test]
    fn registration_is_metered_per_address() {
        let ip: IpAddr = Ipv4Addr::new(192, 0, 2, 44).into();
        let mut t = IpTable::default();
        for i in 0..6 {
            assert!(t.may_register(ip, 6), "registration {i} refused");
        }
        assert!(!t.may_register(ip, 6));
        // an untouched address is not affected by the busy one
        assert!(t.may_register(Ipv4Addr::new(192, 0, 2, 45).into(), 6));
    }
}
