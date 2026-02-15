use clap::{Parser, Subcommand};
use tdx_ql::{
    TDX_REPORT_DATA_SIZE, TDX_REPORT_SIZE, TDX_RTMR_EXTEND_DATA_SIZE, extend_tdx_rtmr,
    get_tdx_report,
};

#[derive(Parser)]
#[command(about = "Simple CLI for tdx-ql", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch a TDX report for the current TD.
    GetReport {
        /// Hex string (64 bytes / 128 hex chars). Defaults to all zeros.
        #[arg(long)]
        report_data: Option<String>,
        /// Debug-print the parsed report struct.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Extend RTMR[2] or RTMR[3] with 48 bytes of data.
    ExtendRtmr {
        /// RTMR index (only 2 or 3 supported by the platform).
        #[arg(long)]
        rtmr_index: u64,
        /// Hex string (48 bytes / 96 hex chars). Defaults to all zeros.
        #[arg(long)]
        extend_data: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::GetReport {
            report_data,
            verbose,
        } => {
            let report_data = match report_data {
                Some(hex) => parse_hex_exact::<TDX_REPORT_DATA_SIZE>(&hex),
                None => Ok([0u8; TDX_REPORT_DATA_SIZE]),
            }
            .unwrap_or_else(|err| exit_with_error(&err));

            let report = get_tdx_report(report_data)
                .unwrap_or_else(|err| exit_with_error(&format!("get_tdx_report failed: {err}")));

            let report_bytes = report.as_ref();
            println!("report_size={} bytes", TDX_REPORT_SIZE);
            println!("report_hex={}", hex_encode(report_bytes));
            if verbose {
                println!("report details: {report:?}");
            }
        }
        Command::ExtendRtmr {
            rtmr_index,
            extend_data,
        } => {
            let extend_data = match extend_data {
                Some(hex) => parse_hex_exact::<TDX_RTMR_EXTEND_DATA_SIZE>(&hex),
                None => Ok([0u8; TDX_RTMR_EXTEND_DATA_SIZE]),
            }
            .unwrap_or_else(|err| exit_with_error(&err));

            extend_tdx_rtmr(rtmr_index, extend_data)
                .unwrap_or_else(|err| exit_with_error(&format!("extend_tdx_rtmr failed: {err}")));

            println!("extended rtmr_index={rtmr_index}");
        }
    }
}

fn parse_hex_exact<const N: usize>(input: &str) -> Result<[u8; N], String> {
    let hex = input.strip_prefix("0x").unwrap_or(input);
    if hex.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, hex.len()));
    }

    let mut out = [0u8; N];
    let bytes = hex.as_bytes();
    for i in 0..N {
        let hi = decode_nibble(bytes[i * 2])?;
        let lo = decode_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn decode_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", b as char)),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = vec![0u8; bytes.len() * 2];
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = TABLE[(b >> 4) as usize];
        out[i * 2 + 1] = TABLE[(b & 0x0f) as usize];
    }
    String::from_utf8(out).expect("hex table is ascii")
}

fn exit_with_error(message: &str) -> ! {
    eprintln!("error: {message}");
    std::process::exit(1);
}
