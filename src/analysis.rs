use std::fmt;
use std::any::Any;
use anyhow::{anyhow, Result};

use crate::{loader::Binary, log::LogLevel};

#[derive(Debug, PartialEq)]
pub enum AnalysisResultType {
    CFG,
    XmmXor,
    Hash,
}

pub struct AnalysisOpts {
    pub log_level: LogLevel,
    pub restrict_function_block: Option<u64>,
    pub restrict_basic_block: Option<u64>,
}

impl fmt::Display for AnalysisResultType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match self {
            AnalysisResultType::CFG => "CFG",
            AnalysisResultType::XmmXor => "XmmXor",
            AnalysisResultType::Hash => "Hash",
        })
    }
}

pub trait AnalysisResult: Any {
    fn get_type(&self) -> AnalysisResultType;
    fn print_result(&self);
}

impl dyn AnalysisResult {
    pub fn as_type<'a, T: 'static>(self: &'a dyn AnalysisResult) -> Result<&'a T> {
        match (self as &dyn Any).downcast_ref::<T>() {
            Some(as_type) => Ok(as_type),
            None => Err(anyhow!("Could not convert analysis result to type")),
        }
    }
}

pub struct AnalysisSet {
    pub opts: AnalysisOpts,
    pub results: Vec<Box<dyn AnalysisResult>>,
}

impl AnalysisSet {
    pub fn get_of_type(&self, result_type: AnalysisResultType) -> Result<&Box<dyn AnalysisResult>> {
        for result in &self.results {
            if result.get_type() == result_type {
                return Ok(result);
            }
        }

        Err(anyhow!("No analysis result of type {}", result_type))
    }
}

pub trait Analysis {
    fn analyze(&self, analyses: &AnalysisSet, binary: &Binary) -> Result<Box<dyn AnalysisResult>>;
}
