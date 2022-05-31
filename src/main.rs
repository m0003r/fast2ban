use crate::parser::regex::RegexParser;
use crate::parser::*;
use crate::ban_buffer::RingBanBuffer;

use serde_derive::Deserialize;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::env::args;
use std::fs::File;
use std::io::{self, prelude::*, BufReader};
use std::net::IpAddr;

mod parser;
mod ban_buffer;

#[derive(Deserialize, Debug)]
struct Config {
    log_file: String,
    log_regex: String,
    requests: usize,
    period: u32,
    date_format: String,
}

fn read_config(config_file: &str) -> Config {
    let config_str = std::fs::read_to_string(config_file)
        .expect(format!("Failed to read config file {}", config_file).as_str());
    toml::from_str(&config_str)
        .expect(format!("Failed to parse config file {}", config_file).as_str())
}

fn main() -> io::Result<()> {
    let config_file = args().nth(1).unwrap_or("config.toml".to_string());
    eprintln!("Using config file {}", config_file);
    // read config
    let config = read_config(&config_file);
    eprintln!("Config: {:#?}", config);

    let reader: Box<dyn BufRead>;
    if config.log_file == "-" {
        reader = Box::new(BufReader::new(io::stdin()));
    } else {
        reader = Box::new(BufReader::new(
            File::open(config.log_file).expect("Failed to open log file"),
        ));
    }

    let parser =
        RegexParser::new(&config.log_regex, &config.date_format).expect("Failed to parse regex");

    let start = std::time::Instant::now();
    let mut ban_tickets = HashMap::<IpAddr, RingBanBuffer>::new();
    let mut line_count = 0;

    for line in reader.lines() {
        if let Err(_) = line {
            eprintln!("Line read error, break!");
            break;
        }
        let line = line?;
        line_count += 1;
        if let Ok(ParseResult { ip, timestamp: dt }) = parser.parse_line(&line) {
            let entry = ban_tickets.entry(ip);
            if let Entry::Occupied(mut entry) = entry {
                let mut buffer = entry.get_mut();
                if buffer.banned {
                    continue;
                }
                let duration = buffer.add_query(dt);
                if let Some(dur) = duration {
                    if dur <= config.period as i64 {
                        buffer.banned = true;
                    }
                }
            } else {
                let mut buffer = RingBanBuffer::new(config.requests);
                buffer.add_query(dt);
                entry.or_insert(buffer);
            }
        }
    }

    let elapsed = start.elapsed();

    let banned_ips: Vec<&IpAddr> = ban_tickets
        .iter()
        .filter(|(_, v)| v.banned)
        .map(|(k, _)| k)
        .collect();

    eprintln!(
        "elapsed {} ms, {} lines parsed, {} lines/s, banned = {}/{}",
        elapsed.as_millis(),
        line_count,
        line_count as f64 / (elapsed.as_millis() as f64 / 1000.0),
        banned_ips.len(),
        ban_tickets.len()
    );

    for i in banned_ips {
        println!("{}", i);
    }
    Ok(())
}
