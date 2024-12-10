#![no_std]
#![cfg_attr(all(feature = "std", target_env = "sgx"), feature(sgx_platform))]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
extern crate alloc;

use alloc::borrow::ToOwned;

#[cfg(feature = "std")]
use std::time::SystemTime;

#[cfg(all(feature = "std", target_os = "linux"))]
use std::fs;

#[cfg(not(target_env = "sgx"))]
use core::arch::x86_64::__cpuid;
use core::arch::x86_64::__rdtscp;
use core::cell::RefCell;
use core::cmp::{self, PartialEq, PartialOrd};
use core::fmt::{self, Debug, Display, Formatter};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use core::ops::Add;

const NANOS_PER_SEC: u64 = 1_000_000_000;

pub trait NativeTime: PartialOrd + Copy + Add<core::time::Duration, Output = Self> + ToOwned {
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
            Err(e) => e.duration()
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

#[derive(Debug, Default)]
pub struct Ticks(AtomicU64);

impl PartialEq<Ticks> for Ticks {
    fn eq(&self, other: &Ticks) -> bool {
        let t = self.0.load(Ordering::Relaxed);
        let o = other.0.load(Ordering::Relaxed);
        t.eq(&o)
    }
}

impl PartialOrd<Ticks> for Ticks {
    fn partial_cmp(&self, other: &Ticks) -> Option<cmp::Ordering> {
        let t = self.0.load(Ordering::Relaxed);
        let o = other.0.load(Ordering::Relaxed);
        t.partial_cmp(&o)
    }
}

impl Add for Ticks {
    type Output = Ticks;

    fn add(self, other: Self) -> Self::Output {
        Ticks(AtomicU64::new(self.0.load(Ordering::Relaxed) + other.0.load(Ordering::Relaxed)))
    }
}

impl Display for Ticks {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{} ticks", self.0.load(Ordering::Relaxed))
    }
}

impl Ticks {
    pub fn new(t: u64) -> Self {
        Ticks(AtomicU64::new(t))
    }

    pub fn now() -> Self {
        Ticks(Rdtscp::read().into())
    }

    pub fn abs_diff(&self, t1: &Ticks) -> Ticks {
        let t0 = self.0.load(Ordering::Relaxed);
        let t1 = t1.0.load(Ordering::Relaxed);

        if t1 > t0 {
            Ticks::new(t1 - t0)
        } else {
            Ticks::new(t0 - t1)
        }
    }

    fn set(&self, t: Ticks) {
        let t = t.0.load(Ordering::Relaxed);
        self.0.store(t, Ordering::Relaxed);
    }

    pub fn from_duration(duration: Duration, freq: &Freq) -> Self {
        let freq = freq.as_u64();
        let ticks_secs = duration.as_secs() * freq;
        let ticks_nsecs = duration.subsec_nanos() as u64 * freq / NANOS_PER_SEC;
        Ticks::new(ticks_secs + ticks_nsecs)
    }

    pub fn as_duration_ex(&self, freq: &Freq) -> Duration {
        let freq = freq.as_u64();
        let ticks = self.0.load(Ordering::Relaxed);

        let time_secs = ticks / freq;
        let time_nsecs = (ticks % freq * NANOS_PER_SEC) / freq;
        let time_nsecs: u32 = time_nsecs.try_into().expect("must be smaller than 1sec");

        Duration::new(time_secs, time_nsecs)
    }

    pub fn elapsed(&self, freq: &Freq) -> Duration {
        let tsc_now = Ticks::now();
        self.abs_diff(&tsc_now).as_duration_ex(&freq)
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
pub struct Freq(AtomicU64);

impl PartialEq<Freq> for Freq {
    fn eq(&self, other: &Freq) -> bool {
        let f = self.0.load(Ordering::Relaxed);
        let o = other.0.load(Ordering::Relaxed);
        f.eq(&o)
    }
}

impl PartialOrd<Freq> for Freq {
    fn partial_cmp(&self, other: &Freq) -> Option<cmp::Ordering> {
        let f = self.0.load(Ordering::Relaxed);
        let o = other.0.load(Ordering::Relaxed);
        f.partial_cmp(&o)
    }
}

impl Debug for Freq {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        let freq = self.as_u64();
        f.debug_struct("Freq")
         .field("freq", &freq)
         .finish()
    }
}

impl Freq {
    fn is_zero(&self) -> bool {
        self.0.load(Ordering::Relaxed) == 0
    }

    fn set(&self, f: &Freq) {
        let f = f.0.load(Ordering::Relaxed);
        self.0.store(f, Ordering::Relaxed);
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum ClockSource {
    TSC,
}

impl Freq {
    pub fn new(crystal_hz: u32, numerator: u32, denominator: u32) -> Self {
        Freq::from_u64(crystal_hz as u64 * numerator as u64 / denominator as u64)
    }

    pub fn from_u64(freq: u64) -> Freq {
        assert!(freq != 0);
        Freq(freq.into())
    }

    pub fn as_u64(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    pub fn estimate(ticks: Ticks, secs: Duration) -> Freq {
        let nsecs = secs.as_secs() as u128 * NANOS_PER_SEC as u128 + secs.subsec_nanos() as u128;
        let estimate = ticks.0.load(Ordering::Relaxed) as u128 * NANOS_PER_SEC as u128 / nsecs;

        Freq(AtomicU64::from(estimate as u64))
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
        // The next time we should contact the external clock source and re-sync
        next_sync: Ticks,
        // Learned frequency
        frequency: Freq,
    },
    NoRdtsc,
}

enum TimeMode<T: NativeTime> {
    Monotonic {
        last_time: RefCell<Option<T>>,
        mutex: AtomicBool,
    },
    NonMonotonic,
}

// RefCell isn't Sync, but we took care of that using the explicity mutex
unsafe impl<T: NativeTime> Sync for TimeMode<T> {}

impl<T: NativeTime> TimeMode<T> {
    pub fn monotonic() -> Self {
        TimeMode::Monotonic {
            last_time: RefCell::new(None),
            mutex: AtomicBool::new(false),
        }
    }

    pub fn non_monotonic() -> Self {
        TimeMode::NonMonotonic
    }

    pub fn observe(&self, now: T) -> T {
        fn lock<T: NativeTime>(mode: &TimeMode<T>) -> Option<&RefCell<Option<T>>> {
            if let TimeMode::Monotonic { mutex, last_time } = mode {
                while mutex.compare_exchange(false, true, Ordering::Acquire, Ordering::Acquire).is_err()
                {}
                Some(&last_time)
            } else {
                None
            }
        }

        fn unlock<T: NativeTime>(mode: &TimeMode<T>) {
            if let TimeMode::Monotonic { mutex, .. } = mode {
                mutex.store(false, Ordering::Release);
            }
        }

        if let Some(last_time) = lock(self) {
            let mut last_time = last_time.borrow_mut();
            let now = match last_time.to_owned() {
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
            };
            drop(last_time);
            unlock(self);
            now
        } else {
            now
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
    // The frequency learned
    frequency: Option<Freq>,
}

impl<T: NativeTime> LearningFreqTscBuilder<T> {
    pub fn new() -> Self {
        LearningFreqTscBuilder {
            frequency_learning_period: Duration::from_secs(1),
            max_acceptable_drift: Duration::from_millis(1),
            max_sync_interval: Duration::from_secs(60),
            time_mode: TimeMode::non_monotonic(),
            frequency: None,
        }
    }

    pub fn set_initial_frequency(mut self, freq: Freq) -> Self {
        self.frequency = Some(freq);
        self
    }

    pub fn initial_frequency(&self) -> &Option<Freq> {
        &self.frequency
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
        let LearningFreqTscBuilder { frequency, max_sync_interval, max_acceptable_drift, frequency_learning_period, time_mode, } = self;
        let tsc_mode = TscMode::Learn {
            max_sync_interval,
            max_acceptable_drift,
            frequency_learning_period,
            next_sync: Ticks::new(0),
            frequency: frequency.unwrap_or(Freq(AtomicU64::from(0))),
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

impl<T: NativeTime> Tsc<T> {
    fn new(tsc_mode: TscMode, time_mode: TimeMode<T>) -> Self {
        let now = T::now();
        let t0 = if let TscMode::NoRdtsc = tsc_mode { Ticks::default() } else { Ticks::now() };
        Tsc {
            t0: (t0, now),
            tsc_mode,
            time_mode,
        }
    }

    fn resync_clocks(&self, current_freq: &Freq, frequency_learning_period: &Duration, max_acceptable_drift: &Duration, max_sync_interval: &Duration) -> Result<Option<(T, Duration, Freq)>, Error> {
        // Fetch actual time
        let system_now = T::now();

        // Calculate new freq
        let diff_system = system_now.abs_diff(&self.t0.1);
        if diff_system < *frequency_learning_period {
            return Ok(None);
        }
        let tsc_now = Ticks::now();
        let estimated_freq = Freq::estimate(self.t0.0.abs_diff(&tsc_now), diff_system);

        // Calculate error
        let now = self.now_ex(current_freq);
        let error = system_now.abs_diff(&now);

        // Calculate the maximum interval we need to re-sync
        let max_sync_interval = if error.is_zero() {
            // We have a very good clock, don't postpone re-sync inevitably (and don't div by zero)
            max_sync_interval.to_owned()
        } else {
            // Common case, estimate interval based on error and max acceptable error
            diff_system * max_acceptable_drift.div_duration_f64(error) as u32
        };

        Ok(Some((system_now, max_sync_interval, estimated_freq)))
    }

    fn now_ex(&self, freq: &Freq) -> T {
        self.t0.1 + self.t0.0.elapsed(freq)
    }

    pub fn now(&self) -> T {
        let now = match &self.tsc_mode {
            TscMode::NoRdtsc => T::now(),
            TscMode::Learn { frequency_learning_period, max_acceptable_drift, max_sync_interval, next_sync, frequency } => {
                let tsc_now = Ticks::now();
                let f = if !frequency.is_zero() {
                    Freq(frequency.as_u64().into())
                } else {
                    let system_now = T::now();
                    let diff_system = system_now.abs_diff(&self.t0.1);
                    if diff_system < *frequency_learning_period {
                        // We don't have enough data to estimate frequency correctly
                        return system_now;
                    }

                    let estimated_freq = Freq::estimate(self.t0.0.abs_diff(&tsc_now), diff_system);
                    frequency.set(&estimated_freq);
                    estimated_freq
                };

                let now = self.now_ex(&f);

                if tsc_now < *next_sync {
                    now
                } else {
                    // Re-estimate freq when a time threshold is reached
                    if let Ok(Some((now, next_sync_interval, estimated_freq))) = self.resync_clocks(&f, &frequency_learning_period, &max_acceptable_drift, &max_sync_interval) {
                        next_sync.set(tsc_now + Ticks::from_duration(next_sync_interval, &estimated_freq));
                        frequency.set(&estimated_freq);
                        return now;
                    }
                    now
                }
            }
            TscMode::Fixed { frequency } => {
                self.now_ex(&frequency)
            }
        };

        self.time_mode.observe(now)
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
    #[cfg(feature = "std")]
    use std::time::SystemTime;

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

            let estimated_freq = Freq::estimate(t1.1.abs_diff(&t0.1), t1.0.duration_since(t0.0).unwrap());
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

    fn clock_drift<T: NativeTime>(builder: impl TscBuilder<T>, test_duration: Duration, max_acceptable_drift: &Duration, monotonic_time: bool) {
        /// There's a test that spits out random time values. Those values can't be used to end the
        /// test
        #[cfg(feature = "std")]
        fn test_now<T: NativeTime>() -> SystemTime {
            SystemTime::now()
        }

        #[cfg(not(feature = "std"))]
        fn test_now<T: NativeTime>() -> T {
            T::now()
        }
        let tsc = builder.build();
        let end = test_now::<T>() + test_duration;
        let mut last = None;

        while test_now::<T>() < end {
            let system_now = T::now();
            let tsc_now = tsc.now();
            let drift = system_now.abs_diff(&tsc_now);
            assert!(drift < *max_acceptable_drift, "Found {:?} drift, (max drift was {:?})", drift, max_acceptable_drift);
            if monotonic_time {
                assert!(last.unwrap_or(tsc_now) <= tsc_now);
                last = Some(tsc_now);
            }

            if system_now.abs_diff(&T::minimum()).as_secs() % 7 == 1 {
                // Every now and then, don't sleep
                #[cfg(feature = "std")]
                std::thread::sleep(Duration::from_micros(10));

                #[cfg(not(feature = "std"))]
                for _i in 0..100000 {}
            }
        }
    }

    #[test]
    #[cfg(all(feature = "std", feature = "rdtsc_tests"))]
    #[cfg(not(target_env = "sgx"))]
    fn clock_drift_default_learning_freq_builder() {
        let tsc_builder: LearningFreqTscBuilder<SystemTime> = LearningFreqTscBuilder::new();
        let max_drift = tsc_builder.max_acceptable_drift().to_owned();
        clock_drift(tsc_builder, test_duration(), &(ADDITIONAL_DRIFT + max_drift), false);
    }

    #[test]
    #[cfg(all(feature = "std", feature = "rdtsc_tests"))]
    #[cfg(not(target_env = "sgx"))]
    fn clock_drift_learning_freq_monotonic() {
        let tsc_builder: LearningFreqTscBuilder<SystemTime> = LearningFreqTscBuilder::new()
            .set_monotonic_time();
        let max_drift = tsc_builder.max_acceptable_drift().to_owned();
        clock_drift(tsc_builder, test_duration(), &(ADDITIONAL_DRIFT + max_drift), false);
    }

    #[test]
    #[cfg(feature = "std")]
    fn clock_drift_no_rdtsc_monotonic() {
        let tsc_builder: NoRdtscTscBuilder<SystemTime> = NoRdtscTscBuilder::new()
            .set_monotonic_time();
        clock_drift(tsc_builder, test_duration(), &ADDITIONAL_DRIFT, true);
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[cfg(all(feature = "std", feature = "rdtsc_tests"))]
    fn clock_drift_fix_freq_monotonic() {
        if let Ok(freq) = Freq::get() {
            let tsc_builder = FixedFreqTscBuilder::new(freq)
                .set_monotonic_time();
            clock_drift(tsc_builder, test_duration(), &ADDITIONAL_DRIFT, true);
        }
    }

    #[cfg(feature = "std")]
    #[derive(Copy, Clone, PartialOrd, PartialEq)]
    // Time in nanoseconds since UNIX_EPOCH
    struct RandTime(u64);

    #[cfg(feature = "std")]
    impl Add<Duration> for RandTime {
        type Output = RandTime;

        fn add(self, other: Duration) -> Self::Output {
            let t = self.0 + other.as_secs() * super::NANOS_PER_SEC + other.subsec_nanos() as u64;
            RandTime(t)
        }
    }

    #[cfg(feature = "std")]
    impl NativeTime for RandTime {
        fn minimum() -> RandTime {
            RandTime(0)
        }

        fn abs_diff(&self, other: &Self) -> Duration {
            Duration::from_nanos(self.0.abs_diff(other.0))
        }

        fn now() -> Self {
            let t = rand::random::<u64>() % 1000;
            RandTime(t)
        }
    }

    #[cfg(all(target_env = "sgx", feature = "rdtsc_tests"))]
    #[derive(Copy, Clone, PartialOrd, PartialEq)]
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


    #[test]
    #[cfg(all(target_env = "sgx", feature = "rdtsc_tests"))]
    fn sgx_time() {
        let tsc_builder: LearningFreqTscBuilder<SgxTime> = LearningFreqTscBuilder::new()
            .set_monotonic_time();
        clock_drift(tsc_builder, test_duration(), &ADDITIONAL_DRIFT, true);
    }
}
