use std::path::{PathBuf};
use anyhow::{Result};
use clap::{Parser};
use clap_num::maybe_hex;

mod log;
mod loader;
mod mem;
mod registers;
mod analysis;
mod cfg;
mod emulator;
mod hashconst;
mod hashfunc;
mod xmmxor;
mod fnv;
mod data_winapi;
mod hashfind;
mod lazyimport;

use crate::analysis::{Analysis, AnalysisOpts, AnalysisSet};
use crate::loader::{load_pe_file};
use crate::log::LogLevel;
use crate::cfg::CFGAnalysis;
use crate::xmmxor::XorAnalysis;
use crate::hashfunc::HashAnalysis;
use crate::lazyimport::LazyImportAnalysis;

const PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(long_about = None)]
struct Cli {
    /// Path to the binary file to analyze
    #[arg(value_name = "FILE")]
    file_path: PathBuf,

    /// Verbosity (0=errors, 1=errors+warnings, 2=debug)
    #[arg(short, long, value_name="VERBOSITY", default_value_t=1)]
    log_level: u64,

    /// Analyze a function at this address (absolute virtual)
    #[arg(short, long, value_name="ADDRESS", value_parser=maybe_hex::<u64>)]
    function_block: Option<u64>,

    /// Analyze a basic block at this address (absolute virtual)
    #[arg(short, long, value_name="ADDRESS", value_parser=maybe_hex::<u64>)]
    basic_block: Option<u64>,
}

pub fn load_and_analyze(file_path: &str, opts: AnalysisOpts) -> Result<AnalysisSet> {
    let pebin = load_pe_file(file_path)?;

    let mut analyses = AnalysisSet {
        opts: opts,
        results: Vec::new()
    };

    analyses.results.push(CFGAnalysis{}.analyze(&analyses, &pebin)?);
    analyses.results.push(HashAnalysis{}.analyze(&analyses, &pebin)?);
    analyses.results.push(XorAnalysis{}.analyze(&analyses, &pebin)?);
    analyses.results.push(LazyImportAnalysis{}.analyze(&analyses, &pebin)?);

    Ok(analyses)
}

fn main() {
    println!("crypti -- version {}", PROGRAM_VERSION);

    let cli = Cli::parse();

    let opts = AnalysisOpts{
        log_level: match cli.log_level {
            0 => LogLevel::Error,
            1 => LogLevel::Warn,
            2 => LogLevel::Debug,
            _ => LogLevel::Warn         // warning level by default
        },
        restrict_function_block: cli.function_block,
        restrict_basic_block: cli.basic_block,
    };

    match load_and_analyze(cli.file_path.as_os_str().to_str().unwrap(), opts) {
        Ok(analyses) => {
            for result in analyses.results {
                result.print_result();
            }
        },
        Err(err) => {
            println!("Error: Could not complete analysis due to errors.");
            println!("{}", err)
        },
    };
}
