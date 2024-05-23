extern crate core;

#[cfg(feature = "automaton")]
use crate::automaton::Automaton;

#[cfg(all(not(feature = "automaton"), not(feature = "simd")))]
use crate::parser::regex::RegexParser;
#[cfg(any(not(feature = "mmap"), not(feature = "simd")))]
use std::io::BufRead;

use crate::ban_buffer::RingBanBuffer;
use crate::parser::*;
use crate::reader::*;

use crate::simd::SimdParser;
use serde_derive::Deserialize;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::env::args;
use std::io;
use std::net::IpAddr;

mod ban_buffer;
mod parser;
mod reader;

#[derive(Deserialize, Debug)]
struct Config {
    log_file: String,
    log_regex: String,
    requests: usize,
    period: u32,
    date_format: String,
    secret: Option<String>,
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
    let secret = config.secret.map(|s| {
        let f = format!("{}{}", chrono::Utc::now().format("%Y%m%d"), s);
        format!("{:x}", md5::compute(f))
    });

    dbg!(&secret);
    #[cfg(all(feature = "automaton", feature = "simd"))]
    {
        compile_error!("Only automaton OR simd allowed")
    }

    let reader;
    let parser;
    #[cfg(feature = "automaton")]
    {
        reader = create_buf_reader(&config.log_file)
            .split(b'\n')
            .map(|line| line.unwrap());
        parser = Automaton {};
    }

    #[cfg(feature = "simd")]
    {
        #[cfg(feature = "mmap")]
        {
            reader = create_mmap_memchr_iter(&config.log_file);
        }
        #[cfg(not(feature = "mmap"))]
        {
            reader = create_buf_reader(&config.log_file)
                .split(b'\n')
                .map(|line| line.unwrap());
        }
        parser = SimdParser::new();
    }

    #[cfg(all(not(feature = "automaton"), not(feature = "simd")))]
    {
        reader = create_buf_reader(&config.log_file)
            .lines()
            .map(|line| line.unwrap());
        parser = RegexParser::new(&config.log_regex, &config.date_format)
            .expect("Failed to parse regex");
    }



    let start = std::time::Instant::now();
    let mut ban_tickets = HashMap::<IpAddr, RingBanBuffer>::new();
    let mut line_count = 0;

    for line in reader {
        line_count += 1;

        if let Ok(ParseResult { ip, timestamp: dt }) = parser.parse_line(&line) {
            let has_secret = secret.as_ref().map(|s| line.contains(s)).unwrap_or(false);

            let entry = ban_tickets.entry(ip);
            if let Entry::Occupied(mut entry) = entry {
                let mut buffer = entry.get_mut();
                if has_secret {
                    buffer.whitelisted = true;
                    continue;
                }
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
                if has_secret {
                    buffer.whitelisted = true;
                } else {
                    buffer.add_query(dt);
                }
                entry.or_insert(buffer);
            }
        }
    }

    let elapsed = start.elapsed();

    let banned_ips: Vec<&IpAddr> = ban_tickets
        .iter()
        .filter(|(_, v)| v.banned && !v.whitelisted)
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
