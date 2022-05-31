use derive_more::Display;
use std::net::IpAddr;

pub mod regex;

#[derive(Debug, Eq, PartialEq)]
pub struct ParseResult {
    pub ip: IpAddr,
    pub timestamp: i64,
}

#[derive(Display, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum ParseError {
    InvalidLine,
    InvalidIP,
    InvalidDateTime,
    Unknown,
}

pub trait LineParser<L> {
    fn parse_line(&self, line: L) -> Result<ParseResult, ParseError>;
}
