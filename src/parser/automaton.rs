#![cfg(feature = "automaton")]

use crate::{LineParser, ParseError, ParseResult};
use std::net::{IpAddr, Ipv4Addr};

pub struct Automaton;

impl LineParser<&[u8]> for Automaton {
    fn parse_line(&self, line: &[u8]) -> Result<ParseResult, ParseError> {
        let mut ip = 0u32;
        let mut cur_grp = 0u32;
        let mut time = 0u32;
        let mut cur_time = 0u32;

        let mut iter = line.iter();
        for c in iter.by_ref() {
            if *c == b'.' {
                ip = ip * 256 + cur_grp;
                cur_grp = 0;
                continue;
            }
            if *c == b' ' {
                break;
            }
            cur_grp = cur_grp * 10 + (*c - b'0') as u32;
        }
        ip = ip * 256 + cur_grp;

        let iter = iter
            .skip(3)
            .skip_while(|c| **c != b' ')
            .skip_while(|c| **c != b':');
        for c in iter {
            if *c == b':' {
                time = time * 60 + cur_time;
                cur_time = 0;
                continue;
            }
            if *c == b' ' {
                break;
            }
            cur_time = cur_time * 10 + (*c - b'0') as u32;
        }
        time = time * 60 + cur_time;
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::from(ip));
        Ok(ParseResult {
            ip,
            timestamp: time as i64,
        })
    }
}
