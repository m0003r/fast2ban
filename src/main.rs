use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use chrono::*;
use regex::Regex;
use std::net::IpAddr;

struct RingBanBuffer {
    timestamps: Vec<Option<i64>>,
    last_index: usize,
}

impl RingBanBuffer {
    fn new(ring_size: usize) -> RingBanBuffer {
        RingBanBuffer {
            timestamps: vec![None; ring_size],
            last_index: 0,
        }
    }

    fn add_query(&mut self, ts: i64) -> Option<i64> {
        self.timestamps[self.last_index] = Some(ts);
        self.last_index = (self.last_index + 1) % self.timestamps.len();

        self.timestamps[self.last_index].map(|prev| ts - prev)
    }
}

struct ParseResult {
    ip: IpAddr,
    timestamp: i64,
}

struct RegexParser {
    regex: Regex,
    date_format: String,
}

impl RegexParser {
    fn new(regex: &str, date_format: &str) -> Self {
        let re = Regex::new(regex).unwrap();
        RegexParser {
            regex: re,
            date_format: date_format.to_string(),
        }
    }

    fn parse_line(&self, line: &str) -> Option<ParseResult> {
        let caps = self.regex.captures(line)?;
        let timestamp = DateTime::parse_from_str(&caps["DT"], &self.date_format).ok()?.timestamp();
        let ip: IpAddr = caps["ip"].parse().ok()?;
        Some(ParseResult { ip, timestamp })
    }
}

fn main() {
    let reader = BufReader::new(File::open("nginx.log").unwrap());
    let parser = RegexParser::new(
        r"^(?P<ip>[\d.]+) - [^ ]+ \[(?P<DT>[^\]]+)\]",
        "%d/%B/%Y:%H:%M:%S %z",
    );

    let mut requests: HashMap<IpAddr, (RingBanBuffer, bool)> = HashMap::new();

    let mut line_count = 0;
    let start = std::time::Instant::now();
    for line in reader.lines() {
        line_count += 1;
        if let Some(ParseResult { ip, timestamp }) = line.ok().and_then(|l| parser.parse_line(&l) ) {
            let entry = requests.entry(ip).or_insert((RingBanBuffer::new(30), false));
            if let Some(delta) = entry.0.add_query(timestamp) {
                if delta < 30 {
                    entry.1 = true;
                }
            };
        }
    }

    let elapsed = start.elapsed();

    let banned_ips: Vec<&IpAddr> = requests.iter()
        .filter(|(_, (_, banned))| *banned)
        .map(|(k, _)| k)
        .collect();

    for ip in banned_ips.iter() {
        println!("{}", ip);
    }

    eprintln!(
        "elapsed {} ms, {} lines parsed, {} lines/s, banned = {}/{}",
        (elapsed.as_micros() as f64 / 1e3),
        line_count,
        line_count as f64 / (elapsed.as_micros() as f64 / 1e6),
        banned_ips.len(),
        requests.len()
    );
}