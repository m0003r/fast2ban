use chrono::{DateTime, Duration, FixedOffset};
use regex::Regex;
use serde_derive::Deserialize;
use std::collections::{HashMap, HashSet};
use std::env::args;
use std::fs::File;
use std::io::{self, prelude::*, BufReader};
use std::net::IpAddr;

struct RingBanBuffer {
    last_queries: Vec<Option<DateTime<FixedOffset>>>,
    last_query_index: usize,
}

impl RingBanBuffer {
    fn new(ring_size: usize) -> RingBanBuffer {
        RingBanBuffer {
            last_queries: vec![None; ring_size],
            last_query_index: 0,
        }
    }

    fn add_query(&mut self, query: DateTime<FixedOffset>) -> Option<Duration> {
        self.last_queries[self.last_query_index] = Some(query);
        self.last_query_index = (self.last_query_index + 1) % self.last_queries.len();

        if let Some(prev) = self.last_queries[self.last_query_index] {
            Some(prev - query)
        } else {
            None
        }
    }
}

#[derive(Deserialize, Debug)]
struct Config {
    log_file: String,
    log_regex: String,
    requests: usize,
    period: usize,
    date_format: String,
}

// read config from TOML file and return a Config struct
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

    if !&config.log_regex.contains("(?P<ip>") {
        panic!("log_regex must contain (?P<ip> ... ) group for IP address");
    }
    if !&config.log_regex.contains("(?P<DT>") {
        panic!("log_regex must contain (?P<DT> ... ) group for datetime");
    }
    let re = Regex::new(&config.log_regex).expect("Failed to compile regex");

    let start = std::time::Instant::now();
    // let mut uas = HashSet::new();
    let mut banned = HashSet::new();
    let mut ban_tickets = HashMap::new();
    let mut line_count = 0;
    let mut dt_errors = 0;

    for line in reader.lines() {
        if let Err(_) = line {
            eprintln!("Line read error, break!");
            break;
        }
        let line = line?;
        line_count += 1;
        let captures = re.captures(&line);
        if let Some(caps) = captures {
            let dt = DateTime::parse_from_str(&caps["DT"], &config.date_format);
            if let Err(_) = dt {
                eprintln!("Failed to parse date {}", &caps["DT"]);
                dt_errors += 1;
                continue;
            }
            let dt = dt.unwrap();
            //parse ip into ipv4
            let ip = caps["ip"].parse();
            if let Err(_) = ip {
                eprintln!("Failed to parse ip {}", &caps["ip"]);
                continue;
            }
            let ip: IpAddr = ip.unwrap();
            if banned.contains(&ip) {
                continue;
            }
            let duration = ban_tickets
                .entry(ip)
                .or_insert(RingBanBuffer::new(config.requests))
                .add_query(dt);
            if let Some(dur) = duration {
                if dur < Duration::seconds(config.period as i64) {
                    banned.insert(ip);
                }
            }
        }
    }
    let elapsed = start.elapsed();
    eprintln!(
        "elapsed {} ms, {} lines parsed, {} datetime errors, {} lines/s, banned = {}/{}",
        elapsed.as_millis(),
        line_count,
        dt_errors,
        line_count as f64 / (elapsed.as_millis() as f64 / 1000.0),
        banned.len(),
        ban_tickets.len()
    );

    for i in banned {
        println!("{}", i);
    }
    Ok(())
}
