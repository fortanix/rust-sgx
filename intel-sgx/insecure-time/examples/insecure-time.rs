use {
    insecure_time::{FixedFreqTscBuilder, Ticks, Tsc, TscBuilder, Freq},
    std::time::{Duration, SystemTime},
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

        println!("{:?}: Estimated frequency = {:?}, reported frequency = {:?}", test_duration, Freq::estimate(t1.1.abs_diff(&t0.1), test_duration), &reported_freq);
        std::thread::sleep(Duration::from_secs(10));
    }
}

fn main() {
    let cli = Cli::parse();

    match cli {
        Cli::TestFixedFreqDrift => test_fixed_frequency_drift(),
        Cli::EstimateFreq => estimate_frequency(),
    }
}
