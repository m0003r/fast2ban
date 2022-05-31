#![cfg(all(not(feature = "automaton"), not(feature = "simd")))]

use crate::parser::{LineParser, ParseError, ParseResult};
use chrono::*;
use derive_more::Display;
use regex::Regex;
use std::net::IpAddr;

#[derive(Debug)]
pub struct RegexParser {
    regex: Regex,
    date_format: String,
}

#[derive(Debug, Display, Eq, PartialEq)]
pub enum RegexError {
    IPGroupExpected,
    DTGroupExpected,
    UncompilableRegex,
}

impl std::error::Error for RegexError {}

impl RegexParser {
    pub fn new(regex: &str, date_format: &str) -> Result<Self, RegexError> {
        if !regex.contains("(?P<ip>") {
            return Err(RegexError::IPGroupExpected);
        }
        if !regex.contains("(?P<DT>") {
            return Err(RegexError::DTGroupExpected);
        }
        let re = Regex::new(regex).or(Err(RegexError::UncompilableRegex))?;
        Ok(RegexParser {
            regex: re,
            date_format: date_format.to_string(),
        })
    }
}

impl LineParser<&str> for RegexParser {
    fn parse_line(&self, line: &str) -> Result<ParseResult, ParseError> {
        let caps = self.regex.captures(&line).ok_or(ParseError::InvalidLine)?;
        let timestamp = DateTime::parse_from_str(&caps["DT"], &self.date_format)
            .or(Err(ParseError::InvalidDateTime))?
            .timestamp();
        let ip: IpAddr = caps["ip"].parse().or(Err(ParseError::InvalidIP))?;
        Ok(ParseResult { ip, timestamp })
    }
}

#[cfg(test)]
mod tests {
    use super::RegexParser;
    use crate::regex::RegexError;
    use crate::{LineParser, ParseError, ParseResult};
    use chrono::{FixedOffset, NaiveDate};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn create_parser() {
        let parser = RegexParser::new(
            r#"^(?P<ip>\d+\.\d+\.\d+\.\d+) - [^ ]+ \[(?P<DT>[^\]]+)\]"#,
            "%d/%B/%Y:%H:%M:%S %z",
        );
        assert!(parser.is_ok());
    }

    #[test]
    fn create_parser_without_dt() {
        let parser = RegexParser::new(r#"^(?P<ip>\d+\.\d+\.\d+\.\d+)"#, "%d/%B/%Y:%H:%M:%S %z");
        assert_eq!(parser.unwrap_err(), RegexError::DTGroupExpected);
    }

    #[test]
    fn create_parser_without_ip() {
        let parser = RegexParser::new(r#""#, "%d/%B/%Y:%H:%M:%S %z");
        assert_eq!(parser.unwrap_err(), RegexError::IPGroupExpected);
    }

    #[test]
    fn create_parser_invalid_regex() {
        let parser = RegexParser::new(
            r#"^(?P<ip>\d+\.\d+\.\d+\.\d+) - [^ ]+ \[(?P<DT>[^\]]+"#,
            "%d/%B/%Y:%H:%M:%S %z",
        );
        assert_eq!(parser.unwrap_err(), RegexError::UncompilableRegex);
    }

    #[test]
    fn parse_line() {
        let parser = good_parser();
        let result = parser.parse_line(r#"1.1.1. - - [....]"#);
        assert_eq!(result.unwrap_err(), ParseError::InvalidLine);

        let result = parser.parse_line(r#"1.1.1.1 - - [....]"#);
        assert_eq!(result.unwrap_err(), ParseError::InvalidDateTime);

        let result = parser.parse_line(r#"12.13.156.1123 - - [25/May/2022:10:36:11 +0300] "GET /"#);
        assert_eq!(result.unwrap_err(), ParseError::InvalidIP);

        let result = parser.parse_line(r#"12.13.156.113 - - [25/May/2022:10:36:11 +0300] "GET /"#);
        assert_eq!(
            result.unwrap(),
            ParseResult {
                ip: IpAddr::V4(Ipv4Addr::new(12, 13, 156, 113)),
                timestamp: chrono::DateTime::<FixedOffset>::from_utc(
                    NaiveDate::from_ymd(2022, 5, 25).and_hms(7, 36, 11),
                    FixedOffset::west(3 * 3600),
                )
                .timestamp()
            }
        );
    }

    fn good_parser() -> RegexParser {
        RegexParser::new(
            r#"^(?P<ip>\d+\.\d+\.\d+\.\d+) - [^ ]+ \[(?P<DT>[^\]]+)\]"#,
            "%d/%B/%Y:%H:%M:%S %z",
        )
        .unwrap()
    }
}
