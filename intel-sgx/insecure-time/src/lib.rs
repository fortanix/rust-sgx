#![no_std]
#![cfg_attr(all(feature = "std", target_env = "sgx"), feature(sgx_platform))]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use alloc::borrow::ToOwned;

#[cfg(feature = "std")]
use std::time::SystemTime;

#[cfg(all(feature = "std", target_os = "linux"))]
use std::fs;

#[cfg(not(target_env = "sgx"))]
use core::arch::x86_64::__cpuid;
use core::arch::x86_64::__rdtscp;
use core::cmp::{PartialEq, PartialOrd};
use core::fmt::{self, Debug, Display, Formatter};
use core::time::Duration;
use core::ops::{Add, RangeInclusive};

const NANOS_PER_SEC: u64 = 1_000_000_000;

pub trait NativeTime: Debug + PartialOrd + Copy + Add<core::time::Duration, Output = Self> + ToOwned {
    fn minimum() -> Self;
    fn abs_diff(&self, other: &Self) -> Duration;
    fn now() -> Self;
}

#[cfg(feature = "std")]
impl NativeTime for SystemTime {
    fn minimum() -> Self {
        SystemTime::UNIX_EPOCH
    }

    fn abs_diff(&self, earlier: &Self) -> Duration {
        // When `earlier` is later than self, `duration_since` returns an error. The error itself
        // includes the duration between the two `SystemTime`s
        match self.duration_since(*earlier) {
            Ok(duration) => duration,
            Err(e) => e.duration(),
        }
    }

    fn now() -> Self {
        SystemTime::now()
    }
}

#[derive(Debug)]
pub enum Error {
    NoInvariantTsc,
    NoCrystalFreqReported,
    UnstableTsc,
    UnexpectedTscInfo,
    UnknownFrequency,
    FrequencyCannotBeDetermined,
    TypeOverflow,
}

#[cfg(not(target_env = "sgx"))]
fn cpuid(leaf: u32, eax: &mut u32, ebx: &mut u32, ecx: &mut u32, edx: &mut u32) {
    unsafe {
        let res = __cpuid(leaf);
        *eax = res.eax;
        *ebx = res.ebx;
        *ecx = res.ecx;
        *edx = res.edx;
    }
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Ticks(u64);

impl Add for Ticks {
    type Output = Result<Ticks, Error>;

    #[inline]
    fn add(self, other: Self) -> Self::Output {
        self.0.checked_add(other.0)
            .ok_or(Error::TypeOverflow)
            .map(Ticks)
    }
}

impl Display for Ticks {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{} ticks", self.0)
    }
}

impl Ticks {
    #[inline]
    pub fn new(t: u64) -> Self {
        Ticks(t)
    }

    pub const fn max() -> Self {
        Ticks(u64::MAX)
    }

    pub fn now() -> Self {
        // The RDTSC instruction reads the time-stamp counter and is guaranteed to
        // return a monotonically increasing unique value whenever executed, except
        // for a 64-bit counter wraparound. Intel guarantees that the time-stamp
        // counter will not wraparound within 10 years after being reset. The period
        // for counter wrap is longer for Pentium 4, Intel Xeon, P6 family, and
        // Pentium processors.
        // Source: Intel x86 manual Volume 3 Chapter 19.17 (Time-stamp counter)
        //
        // However, note that an attacker may arbitarily set this value on the
        // host/hypervisor
        Ticks(Rdtscp::read())
    }

    pub fn abs_diff(&self, t1: Ticks) -> Ticks {
        Ticks::new(self.0.abs_diff(t1.0))
    }

    pub fn from_duration(duration: Duration, freq: Freq) -> Result<Self, Error> {
        let freq = freq.as_u64();
        let ticks_secs = duration.as_secs().checked_mul(freq).ok_or(Error::TypeOverflow)?;
        let ticks_nsecs = (duration.subsec_nanos() as u64)
            .checked_mul(freq).ok_or(Error::TypeOverflow)? / NANOS_PER_SEC;
        Ok(Ticks::new(ticks_secs + ticks_nsecs))
    }

    pub fn as_duration_ex(&self, freq: Freq) -> Duration {
        let freq = freq.as_u64();
        let ticks = self.0;

        let time_secs = ticks / freq;
        let time_nsecs = (ticks % freq * NANOS_PER_SEC) / freq;
        let time_nsecs: u32 = time_nsecs.try_into().expect("must be smaller than 1sec");

        Duration::new(time_secs, time_nsecs)
    }

    /// estimate elapsed time since TSC had `self`-many ticks
    pub fn elapsed(&self, freq: Freq) -> Duration {
        let tsc_now = Ticks::now();
        self.abs_diff(tsc_now).as_duration_ex(freq)
    }
}

pub struct Rdtscp;

impl Rdtscp {
    #[inline(never)]
    pub fn read() -> u64 {
        let mut aux: u32 = 0;
        unsafe { __rdtscp(&mut aux) }
    }

    #[cfg(not(target_env = "sgx"))]
    pub fn is_supported() -> bool {
        let mut eax = 0;
        let mut ebx = 0;
        let mut ecx = 0;
        let mut edx = 0;

        cpuid(0x12, &mut eax, &mut ebx, &mut ecx, &mut edx);
        eax & (0x1 << 1) != 0x0

    }
}

/// Frequency in ticks per second
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Freq(u64);

#[derive(PartialEq, Eq, Debug)]
pub enum ClockSource {
    TSC,
}

impl Freq {
    pub fn new(crystal_hz: u32, numerator: u32, denominator: u32) -> Self {
        Freq(crystal_hz as u64 * numerator as u64 / denominator as u64)
    }

    #[inline(always)]
    pub fn from_u64(freq: u64) -> Freq {
        assert!(freq != 0);
        Freq(freq)
    }

    #[inline(always)]
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn estimate(ticks: Ticks, secs: Duration) -> Freq {
        let nsecs = secs.as_secs() as u128 * NANOS_PER_SEC as u128 + secs.subsec_nanos() as u128;
        let estimate = ticks.0 as u128 * NANOS_PER_SEC as u128 / nsecs;

        Freq(estimate as u64)
    }

    #[cfg(not(target_env = "sgx"))]
    pub fn invariant_tsc() -> bool {
        let mut eax = 0;
        let mut ebx = 0;
        let mut ecx = 0;
        let mut edx = 0;

        cpuid(0x80000007, &mut eax, &mut ebx, &mut ecx, &mut edx);
        edx & (0x1 << 8) != 0
    }

    #[cfg(all(feature = "std", target_os = "linux"))]
    fn kernel_clock_source() -> Option<ClockSource> {
        if fs::read_to_string("/sys/devices/system/clocksource/clocksource0/current_clocksource").ok()?.trim() == "tsc" {
            Some(ClockSource::TSC)
        } else {
            None
        }
    }

    // Based on https://github.com/torvalds/linux/blob/master/arch/x86/kernel/tsc.c#L659
    #[cfg(not(target_env = "sgx"))]
    pub fn get() -> Result<Self, Error> {
        let mut eax_denominator: u32 = 0;
        let mut ebx_numerator: u32 = 0;
        let mut edx: u32 = 0;
        let mut crystal_hz = 0;

        #[cfg(all(feature = "std", target_os = "linux"))]
        if Self::kernel_clock_source() != Some(ClockSource::TSC) {
            return Err(Error::UnstableTsc)
        }

        if !Self::invariant_tsc() {
            return Err(Error::NoInvariantTsc)
        }

        cpuid(0x15, &mut eax_denominator, &mut ebx_numerator, &mut crystal_hz, &mut edx);

        if eax_denominator == 0 || ebx_numerator == 0 {
            return Err(Error::UnexpectedTscInfo)
        }

        // Some Intel SoCs like Skylake and Kabylake don't report the crystal
        // clock, but we can easily calculate it to a high degree of accuracy
        // by considering the crystal ratio and the CPU speed.
        // https://github.com/torvalds/linux/blob/master/arch/x86/kernel/tsc.c#L697-L708
        #[cfg(feature = "estimate_crystal_clock_freq")]
        if crystal_hz == 0 {
            let mut eax_base_mhz = 0;
            let mut ebx = 0;
            let mut ecx = 0;
            let mut edx = 0;

            cpuid(0x16, &mut eax_base_mhz, &mut ebx, &mut ecx, &mut edx);
            crystal_hz = eax_base_mhz * 1000 * 1000 * eax_denominator / ebx_numerator;
        }

        if crystal_hz == 0 {
            Err(Error::NoCrystalFreqReported)
        } else {
            Ok(Freq::new(crystal_hz, ebx_numerator, eax_denominator))
        }
    }
}

enum TscMode {
    Fixed {
        frequency: Freq,
    },
    Learn {
        // The minimum duration we need to learn the TSC frequency
        frequency_learning_period: Duration,
        // The maximum error allowed, before forcing a re-sync
        max_acceptable_drift: Duration,
        // The maximum interval between re-syncing with the external clock source
        max_sync_interval: Duration,
    },
    NoRdtsc,
}

enum TimeMode<T: NativeTime> {
    Monotonic {
        last_time: spin::Mutex<Option<T>>
    },
    NonMonotonic,
}

impl<T: NativeTime> TimeMode<T> {
    fn monotonic() -> Self {
        TimeMode::Monotonic {
            last_time: spin::Mutex::new(None)
        }
    }

    fn non_monotonic() -> Self {
        TimeMode::NonMonotonic
    }

    fn observe(&self, now: T) -> T {
        match self {
            TimeMode::Monotonic { last_time } => {
                let mut last_time = last_time.lock();
                match last_time.to_owned() {
                    Some(last) if last < now => {
                        *last_time = Some(now);
                        now
                    },
                    Some(last) => {
                        last
                    },
                    None => {
                        *last_time = Some(now);
                        now
                    }
                }
            },
            TimeMode::NonMonotonic => now,
        }
    }
}

/// Some CPUs do report the speed of their TSC clock. Others do not or do it incomplete. This Tsc
/// keeps track of the time, and has some capabilities to manage different hardware. Users are able
/// to specify that the used frequency is more a guideline; that more exact frequency should be
/// learned over time to avoid clock drift. There's also an initial time frame in which the
/// frequency is deemed inaccurate, and shouldn't be used.
pub struct Tsc<T: NativeTime> {
    t0: (Ticks, T),
    // The mode in which the Tsc operates
    tsc_mode: TscMode,
    // Time is forced to be monotonic, or not
    time_mode: TimeMode<T>,
    tsc_state: spin::RwLock<TscState<T>>,
}

#[derive(Copy, Clone)]
struct TscState<T> {
    /// the most recent reading of the external clock that is paird with a TSC reading (`recent_ticks`)
    recent_native_time: T,
    /// the most recent reading of the TSC that is paired with a reading of the external clock (`recent_native_time`)
    recent_ticks: Ticks,
    /// The next time we should contact the external clock source and re-sync
    next_sync: Ticks,
    /// Learned frequency
    frequency: Freq,
    /// number of times we estimated the frequency
    freq_estimations: usize,
}

pub trait TscBuilder<T: NativeTime> {
    fn set_monotonic_time(self) -> Self;
    fn build(self) -> Tsc<T>;
}

pub struct NoRdtscTscBuilder<T: NativeTime> {
    // Whether the TSC should be monotonic
    time_mode: TimeMode<T>,
}

impl<T: NativeTime> NoRdtscTscBuilder<T> {
    pub fn new() -> Self {
        NoRdtscTscBuilder {
            time_mode: TimeMode::NonMonotonic,
        }
    }
}

impl<T: NativeTime> TscBuilder<T> for NoRdtscTscBuilder<T> {
    fn set_monotonic_time(mut self) -> Self {
        self.time_mode = TimeMode::monotonic();
        self
    }

    fn build(self) -> Tsc<T> {
        Tsc::new(TscMode::NoRdtsc, self.time_mode)
    }
}

pub struct LearningFreqTscBuilder<T: NativeTime> {
    // The maximum interval between re-syncing with the external clock source
    max_sync_interval: Duration,
    // The maximum error allowed, before forcing a re-sync
    max_acceptable_drift: Duration,
    // The minimum duration we need to learn the TSC frequency
    frequency_learning_period: Duration,
    // Whether the TSC should be monotonic
    time_mode: TimeMode<T>,
}

impl<T: NativeTime> LearningFreqTscBuilder<T> {
    pub fn new() -> Self {
        LearningFreqTscBuilder {
            frequency_learning_period: Duration::from_secs(1),
            max_acceptable_drift: Duration::from_millis(1),
            max_sync_interval: Duration::from_secs(60),
            time_mode: TimeMode::non_monotonic(),
        }
    }

    pub fn set_max_acceptable_drift(mut self, error: Duration) -> Self {
        self.max_acceptable_drift = error;
        self
    }

    pub fn max_acceptable_drift(&self) -> &Duration {
        &self.max_acceptable_drift
    }

    pub fn set_max_sync_interval(mut self, interval: Duration) -> Self {
        self.max_sync_interval = interval;
        self
    }

    pub fn max_sync_interval(&self) -> &Duration {
        &self.max_sync_interval
    }

    pub fn set_frequency_learning_period(mut self, period: Duration) -> Self {
        self.frequency_learning_period = period;
        self
    }

    pub fn frequency_learning_period(&self) -> Duration {
        self.frequency_learning_period
    }
}

impl<T: NativeTime> TscBuilder<T> for LearningFreqTscBuilder<T> {
    fn set_monotonic_time(mut self) -> Self {
        self.time_mode = TimeMode::monotonic();
        self
    }

    fn build(self) -> Tsc<T> {
        let LearningFreqTscBuilder { max_sync_interval, max_acceptable_drift, frequency_learning_period, time_mode } = self;
        let tsc_mode = TscMode::Learn {
            max_sync_interval,
            max_acceptable_drift,
            frequency_learning_period: frequency_learning_period.max(max_sync_interval),
        };
        Tsc::new(tsc_mode, time_mode)
    }
}

pub struct FixedFreqTscBuilder<T: NativeTime> {
    frequency: Freq,
    // Whether the TSC should be monotonic
    time_mode: TimeMode<T>,
}

impl<T: NativeTime> TscBuilder<T> for FixedFreqTscBuilder<T> {
    fn set_monotonic_time(mut self) -> Self {
        self.time_mode = TimeMode::monotonic();
        self
    }

    fn build(self) -> Tsc<T> {
        let tsc_mode = TscMode::Fixed {
            frequency: self.frequency,
        };
        Tsc::new(tsc_mode, self.time_mode)
    }
}

impl<T: NativeTime> FixedFreqTscBuilder<T> {
    pub fn new(frequency: Freq) -> Self {
        FixedFreqTscBuilder {
            frequency,
            time_mode: TimeMode::non_monotonic(),
        }
    }
}

#[derive(Debug)]
enum ResyncError<T> {
    UnreliableTscReading(T),
    UnreliableFreqEstimation(T, Ticks),
}

impl<T: NativeTime> Tsc<T> {
    fn new(tsc_mode: TscMode, time_mode: TimeMode<T>) -> Self {
        let now = T::now();
        let t0 = if let TscMode::NoRdtsc = tsc_mode { Ticks::default() } else { Ticks::now() };

        let (frequency, max_sync_interval) = match &tsc_mode {
            TscMode::Fixed { frequency } => (Some(*frequency), Duration::MAX),
            TscMode::Learn { max_sync_interval, .. } => (None, *max_sync_interval),
            TscMode::NoRdtsc => (None, Duration::MAX),
        };
        let (next_sync, frequency) =
            if let Some((Ok(next_sync), frequency)) = frequency.map(|f| (Ticks::from_duration(max_sync_interval, f), f)) {
                // We won't resync until `max_sync_interval`, use the full period to learn the exact
                // frequency
                (next_sync, frequency)
            } else {
                (Ticks::new(0), Freq(0))
            };
        Tsc {
            t0: (t0, now),
            tsc_mode,
            time_mode,
            tsc_state: spin::RwLock::new(TscState {
                recent_ticks: t0,
                recent_native_time: now,
                next_sync,
                frequency,
                freq_estimations: 0,
            })
        }
    }

    const ACCEPTABLE_FREQ_RANGE: RangeInclusive<u64> = 50_000_000..=100_000_000_000;
    fn resync_clocks(max_acceptable_drift: Duration, max_sync_interval: Duration, state: &TscState<T>) -> Result<(T, Ticks, Duration, Freq), ResyncError<T>> {
        let (system_now, tsc_now) = match Self::get_system_now_and_tsc(max_sync_interval, Some(state.frequency)) {
            Ok(st) => st,
            Err(system_now) => return Err(ResyncError::UnreliableTscReading(system_now)),
        };

        // Calculate new freq
        let diff_system = system_now.abs_diff(&state.recent_native_time);
        let estimated_freq = Freq::estimate(state.recent_ticks.abs_diff(tsc_now), diff_system);

        if tsc_now.0 < state.recent_ticks.0
            || (state.freq_estimations > 5 && estimated_freq.as_u64().abs_diff(state.frequency.as_u64()) > state.frequency.as_u64() / 8)
            || !Self::ACCEPTABLE_FREQ_RANGE.contains(&estimated_freq.as_u64())
        {
            return Err(ResyncError::UnreliableFreqEstimation(system_now, tsc_now));
        }
        // Calculate error
        let now = state.recent_native_time + state.recent_ticks.abs_diff(tsc_now).as_duration_ex(state.frequency);
        let error = system_now.abs_diff(&now);

        // `.min(5.0)` means next sync interval will be at most 5 times the current sync interval.
        // It also avoids overflow panics.
        let next_sync_interval = diff_system.mul_f64(max_acceptable_drift.div_duration_f64(error).min(5.0));
        let next_sync_interval = next_sync_interval.min(max_sync_interval);
        Ok((system_now, tsc_now, next_sync_interval, estimated_freq))
    }

    /// Gets current system time and tsc. Returns an error if it observes too much
    /// delay between the two measurements.
    fn get_system_now_and_tsc(max_sync_interval: Duration, current_freq_estimation: Option<Freq>) -> Result<(T, Ticks), T> {
        let tsc_before = current_freq_estimation.is_some().then(Ticks::now);
        let system_now = T::now();
        let tsc_after = Ticks::now();
        if let (Some(current_freq_estimation), Some(tsc_before)) = (current_freq_estimation, tsc_before) {
            let acceptable_lag = Duration::from_millis(10).max(max_sync_interval / 1000);
            if tsc_after.abs_diff(tsc_before).as_duration_ex(current_freq_estimation) > acceptable_lag {
                Err(system_now)
            } else {
                Ok((system_now, tsc_after))
            }
        } else {
            Ok((system_now, tsc_after))
        }
    }

    fn now_internal(&self) -> T {
        match &self.tsc_mode {
            TscMode::NoRdtsc => T::now(),
            TscMode::Learn { frequency_learning_period, max_acceptable_drift, max_sync_interval } => {
                let state = *self.tsc_state.read();
                let (tsc_now, state) = if state.frequency.as_u64() != 0 {
                    (Ticks::now(), state)
                } else {
                    let (system_now, tsc_now) = match Self::get_system_now_and_tsc(*max_sync_interval, None) {
                        Ok(st) => st,
                        Err(system_now) => return system_now,
                    };
                    let diff_system = system_now.abs_diff(&state.recent_native_time);
                    if system_now.abs_diff(&self.t0.1) < *frequency_learning_period {
                        // We don't have enough data to estimate frequency correctly
                        return system_now;
                    }

                    let estimated_freq = Freq::estimate(state.recent_ticks.abs_diff(tsc_now), diff_system);
                    let mut state = self.tsc_state.upgradeable_read().upgrade();
                    state.frequency = estimated_freq;
                    (tsc_now, *state)
                };

                if tsc_now < state.next_sync {
                    state.recent_native_time + state.recent_ticks.elapsed(state.frequency)
                } else {
                    // Re-estimate freq when a time threshold is reached
                    match Self::resync_clocks(*max_acceptable_drift, *max_sync_interval, &state) {
                        Ok((now, ticks, next_sync_interval, estimated_freq)) => {
                            let new_freq_estimations = state.freq_estimations + 1;
                            if now.abs_diff(&self.t0.1) < *frequency_learning_period {
                                // We don't have enough data to estimate frequency correctly
                                return now;
                            }
                            // exponential averaging to reduce noise
                            let w = (state.recent_ticks.elapsed(state.frequency).as_secs_f64() * 0.4).clamp(0.001, 0.9);
                            let new_freq = Freq::from_u64(
                                (estimated_freq.as_u64() as f64 * w + state.frequency.as_u64() as f64 * (1.0 - w)) as u64
                            );
                            // When `next_tsc` overflows, the system has been running for over 10
                            // years, or an attacker manipulated the TSC value. As we can't trust TSC
                            // anyway, we do the simple thing and continue trying to sync
                            let next_sync_ticks = Ticks::from_duration(next_sync_interval, estimated_freq).unwrap_or(Ticks::max());
                            // this instead of self.tsc_state.write() to avoid starvation
                            let mut state = self.tsc_state.upgradeable_read().upgrade();
                            state.freq_estimations = new_freq_estimations;
                            if let Ok(next_tsc) = tsc_now + next_sync_ticks {
                                state.next_sync = next_tsc;
                            }
                            state.frequency = new_freq;
                            state.recent_ticks = ticks;
                            state.recent_native_time = now;
                            now
                        },
                        Err(ResyncError::UnreliableTscReading(now)) => now,
                        Err(ResyncError::UnreliableFreqEstimation(now, ticks)) => {
                            let mut state = self.tsc_state.upgradeable_read().upgrade();
                            state.recent_ticks = ticks;
                            state.recent_native_time = now;
                            now
                        }
                    }
                }
            }
            TscMode::Fixed { frequency } => {
                self.t0.1 + self.t0.0.elapsed(*frequency)
            }
        }
    }

    #[inline]
    pub fn now(&self) -> T {
        let now = self.now_internal();
        self.time_mode.observe(now)
    }

    /// current estimate of the TSC frequency
    pub fn frequency_estimate(&self) -> Option<Freq> {
        match &self.tsc_mode {
            TscMode::Fixed { frequency } => Some(*frequency),
            TscMode::Learn { .. } => Some(self.tsc_state.read().frequency).filter(|freq| freq.0 != 0),
            TscMode::NoRdtsc => None,
        }
    }

    /// number of clock resyncs and frequency estimations done so far
    pub fn resyncs(&self) -> usize {
        self.tsc_state.read().freq_estimations
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "rdtsc_tests")]
    use super::LearningFreqTscBuilder;
    use super::{NativeTime, NoRdtscTscBuilder, TscBuilder};
    #[cfg(not(target_env = "sgx"))]
    use super::{FixedFreqTscBuilder, Freq, Tsc, Ticks};

    use core::ops::Add;
    use core::time::Duration;
    #[cfg(all(feature = "std", feature = "rdtsc_tests", not(target_env = "sgx")))]
    use std::borrow::ToOwned;
    #[cfg(feature = "std")]
    use {
        std::time::SystemTime,
        std::thread,
    };

    #[cfg(not(target_env = "sgx"))]
    fn diff_system_time(t0: SystemTime, t1: SystemTime) -> Duration {
        let diff = if t0 < t1 { t1.duration_since(t0) } else { t0.duration_since(t1) };
        diff.unwrap()
    }

    fn test_duration() -> Duration {
        if cfg!(feature = "long_duration_tests") {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(5)
        }
    }

    const ADDITIONAL_DRIFT: Duration = Duration::from_millis(100);

    #[test]
    #[cfg(feature = "std")]
    fn max_difference() {
        let end = SystemTime::now() + test_duration();
        let mut max = Duration::from_nanos(0);

        while SystemTime::now() < end {
            let t0 = SystemTime::now();
            let t1 = SystemTime::now();
            let diff = t1.duration_since(t0).unwrap();
            if max < diff {
                max = diff;
            }

            assert!(diff < ADDITIONAL_DRIFT, "{:?} difference between calls", diff);
        }
        //Seen max differences of up to 28ms
        //panic!("End of test, max difference = {:?}", max);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn verify_frequency_reported() {
        if let Ok(freq) = Freq::get() {
            let t0 = (SystemTime::now(), Ticks::now());
            std::thread::sleep(Duration::from_secs(2));
            let t1 = (SystemTime::now(), Ticks::now());

            let estimated_freq = Freq::estimate(t1.1.abs_diff(t0.1), t1.0.duration_since(t0.0).unwrap());
            let low_estimate = Freq::from_u64(estimated_freq.as_u64() * 99 / 100);
            let high_estimate = Freq::from_u64(estimated_freq.as_u64() * 101 / 100);
            assert!(low_estimate.as_u64() <= freq.as_u64() && freq.as_u64() <= high_estimate.as_u64(), "Expected frequency between {:?} and {:?}, got {:?}", low_estimate, high_estimate, freq);
        }
    }

    #[test]
    #[cfg(all(feature = "std", target_os = "linux"))]
    fn verify_cpu_reported_freq() {
        if let Ok(freq) = Freq::get() {
            let tsc: Tsc<SystemTime> = FixedFreqTscBuilder::new(freq)
                .build();
            let t0 = (SystemTime::now(), tsc.now());
            loop {
                let t1 = (SystemTime::now(), tsc.now());
                let diff = diff_system_time(t1.0, t1.1);
                assert!(diff < ADDITIONAL_DRIFT, "Found diff between clocks of {:?} after {:?}", diff, diff_system_time(t0.0, t1.0));

                std::thread::sleep(Duration::from_secs(2));
                if test_duration() < diff_system_time(t1.1, t0.1) {
                    break;
                }
            }
        }
    }

    fn clock_drift<T: NativeTime, R: NativeTime>(builder: impl TscBuilder<T>, test_duration: Duration, max_acceptable_drift: &Duration, monotonic_time: bool) {
        let tsc = builder.build();
        let reference_start = R::now();
        let tsc_start = tsc.now();
        let end = R::now() + test_duration;
        let mut last = None;

        while R::now() < end {
            let reference_now = R::now();
            let tsc_now = tsc.now();
            let reference_duration = reference_now.abs_diff(&reference_start);
            let tsc_duration = tsc_now.abs_diff(&tsc_start);
            let drift = reference_duration.abs_diff(tsc_duration);
            assert!(drift < *max_acceptable_drift, "Found {:?} drift, (max drift was {:?} after {}ms)", drift, max_acceptable_drift, reference_duration.as_millis());
            if monotonic_time {
                assert!(last.unwrap_or(tsc_now) <= tsc_now, "Time ran backwards (last: {:?}, now: {:?})", last, tsc_now);
                last = Some(tsc_now);
            }

            #[cfg(feature = "std")]
            std::thread::sleep(Duration::from_micros(10));
        }
    }

    #[test]
    #[cfg(all(feature = "std", feature = "rdtsc_tests"))]
    #[cfg(not(target_env = "sgx"))]
    fn clock_drift_default_learning_freq_builder() {
        let tsc_builder: LearningFreqTscBuilder<SystemTime> = LearningFreqTscBuilder::new();
        let max_drift = tsc_builder.max_acceptable_drift().to_owned();
        clock_drift::<SystemTime, SystemTime>(tsc_builder, test_duration(), &(ADDITIONAL_DRIFT + max_drift), false);
    }

    #[test]
    #[cfg(all(feature = "std", feature = "rdtsc_tests"))]
    #[cfg(not(target_env = "sgx"))]
    fn clock_drift_learning_freq_monotonic() {
        let tsc_builder: LearningFreqTscBuilder<SystemTime> = LearningFreqTscBuilder::new()
            .set_monotonic_time();
        let max_drift = tsc_builder.max_acceptable_drift().to_owned();
        clock_drift::<SystemTime, SystemTime>(tsc_builder, test_duration(), &(ADDITIONAL_DRIFT + max_drift), false);
    }

    #[test]
    #[cfg(feature = "std")]
    fn clock_drift_no_rdtsc_monotonic() {
        let tsc_builder: NoRdtscTscBuilder<SystemTime> = NoRdtscTscBuilder::new()
            .set_monotonic_time();
        clock_drift::<SystemTime, SystemTime>(tsc_builder, test_duration(), &ADDITIONAL_DRIFT, true);
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[cfg(all(feature = "std", feature = "rdtsc_tests"))]
    fn clock_drift_fix_freq_monotonic() {
        if let Ok(freq) = Freq::get() {
            let tsc_builder = FixedFreqTscBuilder::<SystemTime>::new(freq)
                .set_monotonic_time();
            clock_drift::<SystemTime, SystemTime>(tsc_builder, test_duration(), &ADDITIONAL_DRIFT, true);
        }
    }

    #[cfg(all(target_env = "sgx", feature = "rdtsc_tests"))]
    #[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
    // Time in nanoseconds since UNIX_EPOCH
    struct SgxTime(u64);

    #[cfg(all(target_env = "sgx", feature = "rdtsc_tests"))]
    impl Add<Duration> for SgxTime {
        type Output = SgxTime;

        fn add(self, other: Duration) -> Self::Output {
            let t = self.0 + other.as_secs() * super::NANOS_PER_SEC + other.subsec_nanos() as u64;
            SgxTime(t)
        }
    }

    #[cfg(all(target_env = "sgx", feature = "rdtsc_tests"))]
    impl NativeTime for SgxTime {
        fn minimum() -> SgxTime {
            SgxTime(0)
        }

        fn abs_diff(&self, other: &Self) -> Duration {
            Duration::from_nanos(self.0.abs_diff(other.0))
        }

        fn now() -> Self {
            let t = unsafe { std::os::fortanix_sgx::usercalls::raw::insecure_time() };
            SgxTime(t)
        }
    }

    #[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
    // A source of time that mimics a system under very heavy load; it takes a very long time
    // before the result of the time request is serviced.
    // Time in nanoseconds since UNIX_EPOCH
    struct LaggingSystemTime(SystemTime);

    impl LaggingSystemTime {
        const fn system_lag() -> Duration {
            Duration::from_secs(3)
        }
    }

    #[cfg(feature = "std")]
    impl Add<Duration> for LaggingSystemTime {
        type Output = LaggingSystemTime;

        fn add(self, other: Duration) -> Self::Output {
            LaggingSystemTime(self.0 + other)
        }
    }

    #[cfg(feature = "std")]
    impl NativeTime for LaggingSystemTime {
        fn minimum() -> Self {
            LaggingSystemTime(SystemTime::minimum())
        }

        fn abs_diff(&self, earlier: &Self) -> Duration {
            self.0.abs_diff(&earlier.0)
        }

        fn now() -> Self {
            let now = SystemTime::now();
            thread::sleep(Self::system_lag());
            LaggingSystemTime(now)
        }
    }

    #[test]
    #[cfg(all(feature = "std", feature = "rdtsc_tests"))]
    fn very_lagging_system_time() {
        let tsc_builder: LearningFreqTscBuilder<LaggingSystemTime> = LearningFreqTscBuilder::new()
            .set_monotonic_time();
        clock_drift::<_, SystemTime>(tsc_builder, test_duration(), &(LaggingSystemTime::system_lag() * 3), true);
    }

    #[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
    // A source of time that mimics a system under very heavy load; it takes a very long time
    // before the result of the time request is serviced.
    // Time in nanoseconds since UNIX_EPOCH
    struct HighVariationSystemTime(SystemTime);

    impl HighVariationSystemTime {
        pub fn variation() -> Duration {
            Duration::from_secs(10)
        }
    }

    #[cfg(feature = "std")]
    impl Add<Duration> for HighVariationSystemTime {
        type Output = HighVariationSystemTime ;

        fn add(self, other: Duration) -> Self::Output {
            HighVariationSystemTime(self.0 + other)
        }
    }

    #[cfg(feature = "std")]
    impl NativeTime for HighVariationSystemTime {
        fn minimum() -> Self {
            HighVariationSystemTime(SystemTime::minimum())
        }

        fn abs_diff(&self, earlier: &Self) -> Duration {
            self.0.abs_diff(&earlier.0)
        }

        fn now() -> Self {
            let now = SystemTime::now();
            let variation = Duration::from_secs(rand::random::<u64>() % HighVariationSystemTime::variation().as_secs());
            if rand::random::<bool>() {
                HighVariationSystemTime(now + variation)
            } else {
                HighVariationSystemTime(now - variation)
            }
        }
    }

    #[test]
    #[cfg(all(feature = "std", feature = "rdtsc_tests"))]
    #[cfg(not(target_env = "sgx"))]
    fn high_variation_system_time_lag() {
        for monotonic in [false, true] {
            for _run in 0..30 {
                let tsc_builder: LearningFreqTscBuilder<HighVariationSystemTime> = LearningFreqTscBuilder::new()
                        .set_monotonic_time();
                clock_drift::<_, SystemTime>(tsc_builder, Duration::from_secs(1), &(2 * HighVariationSystemTime::variation()), monotonic);
            }
        }
    }

    #[test]
    #[cfg(all(feature = "std", feature = "rdtsc_tests", feature = "long_duration_tests"))]
    #[cfg(not(target_env = "sgx"))]
    fn high_variation_system_time_drift() {
        let tsc_builder: LearningFreqTscBuilder<HighVariationSystemTime> = LearningFreqTscBuilder::new()
                .set_frequency_learning_period(Duration::from_secs(120))
                .set_max_acceptable_drift(Duration::from_millis(1))
                .set_max_sync_interval(Duration::from_secs(60))
                .set_monotonic_time();

        // TSC computes the time based on two `HighVariationSystemTime` at worst this means a
        // variation of `2 * HighVariationSystemTime::variation()` in addition to its max
        // acceptable drift
        clock_drift::<_, SystemTime>(tsc_builder, Duration::from_secs(180), &(2 * HighVariationSystemTime::variation() + Duration::from_millis(1)), true);
    }

    #[test]
    #[cfg(all(feature = "std", feature = "rdtsc_tests"))]
    fn build_time_learning_freq_tsc_builder() {
        let tsc_builder: LearningFreqTscBuilder<HighVariationSystemTime> = LearningFreqTscBuilder::new()
            .set_monotonic_time();
        let t0 = SystemTime::now();
        let tsc = tsc_builder.build();
        let build_time = SystemTime::now().duration_since(t0).unwrap();
        assert!(build_time < Duration::from_millis(10), "Building tsc took {} ms", build_time.as_millis());

        let t0 = SystemTime::now();
        let _t = tsc.now();
        let now_time =  SystemTime::now().duration_since(t0).unwrap();
        assert!(now_time < Duration::from_millis(10), "tsc.now() took {} ms", now_time.as_millis());
    }

    #[test]
    #[cfg(all(target_env = "sgx", feature = "rdtsc_tests"))]
    fn sgx_time() {
        let tsc_builder: LearningFreqTscBuilder<SgxTime> = LearningFreqTscBuilder::new()
            .set_monotonic_time();
        // WARNING: Its up to the caller to ensure that the enclave runner used for this test does
        // not enable rdtsc-based time within the enclave
        clock_drift::<_, SystemTime>(tsc_builder, test_duration(), &ADDITIONAL_DRIFT, true);
    }
}
