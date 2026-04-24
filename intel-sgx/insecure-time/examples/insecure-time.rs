use insecure_time::{FixedFreqTscBuilder, Freq, NativeTime, Ticks, Tsc, TscBuilder};
use rand::{distributions::Uniform, prelude::Distribution, thread_rng};
use std::{
    ops::Add,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{Duration, Instant, SystemTime},
    u64,
};
use clap::Parser;

fn diff_system_time(t0: SystemTime, t1: SystemTime) -> Duration {
    let diff = if t0 < t1 { t1.duration_since(t0) } else { t0.duration_since(t1) };
    diff.unwrap()
}

#[derive(Parser)]
enum Cli {
    TestFixedFreqDrift,
    EstimateFreq,
    LearningFreqTsc {
        /// frequency sync period (`max_sync_interval`) in milliseconds
        #[arg(long, default_value_t = 5000)]
        sync_ms: u64,
        /// simulate slow calls to system time by wating randomly up to this much in microseconds
        #[arg(long, default_value_t = 0)]
        system_time_slowness_micros: u64,
        /// Max acceptable drift passed to LearningFreqTscBuilder
        #[arg(long, default_value_t = 1000)]
        max_acceptable_drift_micros: u64,
        /// `frequency_learning_period` passed to LearningFreqTscBuilder
        #[arg(long, default_value_t = 5000)]
        freq_learn_ms: u64,
    },
}

fn test_fixed_frequency_drift() {
    let freq_reported = Freq::get().expect("Failure, the processor doesn't (fully) report the TSC speed");

    // Don't resync clocks and don't learn frequency
    let tsc: Tsc<SystemTime> = FixedFreqTscBuilder::new(freq_reported)
        .build();
    let t0 = (SystemTime::now(), tsc.now());
    let max_drift = Duration::from_nanos(0);

    loop {
        let t1 = (SystemTime::now(), tsc.now());
        let test_duration = diff_system_time(t0.0, t1.0);
        let drift = diff_system_time(t1.0, t1.1);
        let max_drift = max_drift.max(drift);

        println!("Running for {:?} drift = {:?} (max drift = {:?})", test_duration, drift, max_drift);
        assert!(drift < Duration::from_secs(100), "Found diff between clocks of {:?} after {:?}", drift, diff_system_time(t0.0, t1.0));

        std::thread::sleep(Duration::from_secs(100));
    }
}

fn estimate_frequency() {
    let t0 = (SystemTime::now(), Ticks::now());
    let reported_freq = Freq::get().expect("Couldn't get reported frequency");

    loop {
        let t1 = (SystemTime::now(), Ticks::now());
        let test_duration = diff_system_time(t0.0, t1.0);

        println!("{:?}: Estimated frequency = {:?}, reported frequency = {:?}", test_duration, Freq::estimate(t1.1.abs_diff(t0.1), test_duration), &reported_freq);
        std::thread::sleep(Duration::from_secs(10));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
struct SystemTimeSource(Duration);

impl Add<Duration> for SystemTimeSource {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs)
    }
}

static SYSTEM_TIME_NOW_CALLS: AtomicUsize = AtomicUsize::new(0);
static SYSTEM_TIME_SLOWNESS_MICROS: AtomicU64 = AtomicU64::new(0);
impl NativeTime for SystemTimeSource {
    fn minimum() -> Self {
        todo!()
    }

    fn abs_diff(&self, other: &Self) -> Duration {
        self.0.abs_diff(other.0)
    }

    fn now() -> Self {
        SYSTEM_TIME_NOW_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let slowness_micros = SYSTEM_TIME_SLOWNESS_MICROS.load(Ordering::Relaxed);
        let res = Self(
            SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap(),
        );
        if slowness_micros > 0 {
            let delay = Duration::from_micros(Uniform::new_inclusive(0, slowness_micros).sample(&mut thread_rng()));
            let now = Instant::now();
            while now.elapsed() < delay {}
        }
        res
    }
}

fn learning_freq_tsc(sync_interval_millis: u64, max_acceptable_drift_micros: u64, frequency_learning_period_millis: u64) {
    let tsc = insecure_time::LearningFreqTscBuilder::<SystemTimeSource>::new()
        .set_frequency_learning_period(Duration::from_millis(frequency_learning_period_millis))
        .set_max_acceptable_drift(Duration::from_micros(max_acceptable_drift_micros))
        .set_max_sync_interval(Duration::from_millis(sync_interval_millis))
        .set_monotonic_time()
        .build();

    let mut max_drift_nanos = 0i128;
    let (mut min_freq_estimate, mut max_freq_estimate) = (None, None);
    let mut last_freq_estimate = None;
    let mut last_print = Duration::ZERO;
    let mut sum_drift_sq = 0i128;
    for i in 0usize.. {
        let system_time_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let tsc_now = tsc.now();

        let drift = tsc_now.0.as_nanos() as i128 - system_time_now.as_nanos() as i128;

        sum_drift_sq += drift * drift;
        if max_drift_nanos.abs() < drift.abs() {
            max_drift_nanos = drift;
        }

        if system_time_now - last_print >= Duration::from_millis(1000) {
            let dirft_rms = ((sum_drift_sq / (i as i128 + 1)) as f64).sqrt();
            println!("iter {i} - tsc drift: max: {:.2}μs, rms: {:.2}μs, current: {:.2}μs",
                max_drift_nanos as f64 / 1000.0,
                dirft_rms as f64 / 1000.0,
                drift as f64 / 1000.0
            );
            let freq_estimate = tsc.frequency_estimate().map(|f| f.as_u64());
            min_freq_estimate = freq_estimate.map(|f| f.min(min_freq_estimate.unwrap_or(u64::MAX)));
            max_freq_estimate = freq_estimate.map(|f| f.max(max_freq_estimate.unwrap_or(0)));

            let freq_change_permill = (freq_estimate.unwrap_or(0) as f64 - last_freq_estimate.unwrap_or(0) as f64) / last_freq_estimate.unwrap_or(0) as f64 * 1000_000.0;
            last_freq_estimate = freq_estimate;

            println!("freq estimate: {:?} (change: {:.3} PPM), min: {:?}, max: {:?}, spread: {}Hz",
                freq_estimate, freq_change_permill,
                min_freq_estimate, max_freq_estimate, max_freq_estimate.unwrap_or(0).saturating_sub(min_freq_estimate.unwrap_or(u64::MAX))
            );
            println!("System time reads: {}, tsc resyncs: {}", SYSTEM_TIME_NOW_CALLS.load(Ordering::Relaxed), tsc.resyncs());
            println!("---");
            last_print = system_time_now;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}


fn main() {
    let cli = Cli::parse();

    match cli {
        Cli::TestFixedFreqDrift => test_fixed_frequency_drift(),
        Cli::EstimateFreq => estimate_frequency(),
        Cli::LearningFreqTsc { sync_ms, system_time_slowness_micros, max_acceptable_drift_micros, freq_learn_ms } => {
            SYSTEM_TIME_SLOWNESS_MICROS.store(system_time_slowness_micros, Ordering::Relaxed);
            learning_freq_tsc(sync_ms, max_acceptable_drift_micros, freq_learn_ms)
        },
    }
}
