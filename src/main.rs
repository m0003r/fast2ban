#![feature(stdsimd)]
#![feature(portable_simd)]

use memchr::memchr;
use chrono::{DateTime, Duration, FixedOffset, NaiveDateTime, NaiveTime};
use lazy_static::lazy_static;
use regex::Regex;
use serde_derive::Deserialize;
use std::arch::x86_64::*;
use std::collections::hash_map::Entry;
use std::collections::{HashMap};
use std::env::args;
use std::fs::File;
use std::io::{self, prelude::*, BufReader};
use std::mem::transmute;
use std::net::{IpAddr, Ipv4Addr};
use std::simd::u64x2;
use memmap::MmapOptions;

struct RingBanBuffer {
    last_queries: Vec<Option<NaiveTime>>,
    last_query_index: usize,
    banned: bool,
}

impl RingBanBuffer {
    fn new(ring_size: usize) -> RingBanBuffer {
        RingBanBuffer {
            last_queries: vec![None; ring_size],
            last_query_index: 0,
            banned: false,
        }
    }

    fn add_query(&mut self, query: NaiveTime) -> Option<Duration> {
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

fn init_shuffle_table() {
    let mut len: [usize; 4] = [0; 4];
    len[0] = 1;
    while len[0] <= 3 {
        len[1] = 1;
        while len[1] <= 3 {
            len[2] = 1;
            while len[2] <= 3 {
                len[3] = 1;
                while len[3] <= 3 {
                    let mut slen = len[0] + len[1] + len[2] + len[3] + 4;
                    let mut rem = 16 - slen;
                    let mut rmask = 0;
                    while rmask < (1 << rem) {
                        let mut mask = 0;
                        let mut shuf: [i8; 16] = [-1; 16];
                        let shuf_addr = &shuf as *const i8;
                        let mut pos = 0;
                        let mut i = 0;
                        while i < 4 {
                            let mut j = 0;
                            while j < len[i] {
                                shuf[((3 - i) * 4 + (len[i] - 1 - j))] = pos;
                                pos += 1;
                                j += 1
                            }
                            mask ^= (1) << pos;
                            pos += 1;
                            i += 1
                        }
                        mask ^= rmask << slen;
                        unsafe {
                            _mm_store_si128(&mut SHUFFLE_TABLE[mask], _mm_loadu_si128(shuf_addr as *const __m128i));
                        }
                        rmask += 1
                    }
                    len[3] += 1
                }
                len[2] += 1
            }
            len[1] += 1
        }
        len[0] += 1
    }
}

static mut SHUFFLE_TABLE: [__m128i; 65536] = [unsafe { transmute(0_i128) }; 65536];

unsafe fn print_m128i(m: __m128i) {
    let mut v = [0_u8; 16];
    _mm_storeu_si128(&mut v as *mut _ as *mut __m128i, m);
    println!("{:?}", v);
}

fn parse_ip_simd(x: &[u8]) -> IpAddr {
    let result: u32;
    unsafe {
        let input = _mm_lddqu_si128(x.as_ptr() as *const __m128i); //"192.167.1.3"
        let input = _mm_sub_epi8(input, _mm_set1_epi8(b'0' as i8)); //1 9 2 254 1 6 7 254 1 254 3 208 245 0 8 40
        let cmp = input; //...X...X.X.XX...  (signs)
        let mask = _mm_movemask_epi8(cmp); //6792 - magic index
        let shuf = SHUFFLE_TABLE[mask as usize]; //10 -1 -1 -1 8 -1 -1 -1 6 5 4 -1 2 1 0 -1
        let arr = _mm_shuffle_epi8(input, shuf); //3 0 0 0 | 1 0 0 0 | 7 6 1 0 | 2 9 1 0
        let coeffs = _mm_set_epi8(0, 100, 10, 1, 0, 100, 10, 1, 0, 100, 10, 1, 0, 100, 10, 1);
        let prod = _mm_maddubs_epi16(coeffs, arr); //3 0 | 1 0 | 67 100 | 92 100
        let prod = _mm_hadd_epi16(prod, prod); //3 | 1 | 167 | 192 | ? | ? | ? | ?
        let imm = _mm_set_epi8(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6, 4, 2, 0);
        let prod = _mm_shuffle_epi8(prod, imm);
        result = transmute(_mm_extract_epi32::<0>(prod))
    }
    IpAddr::V4(Ipv4Addr::from(result))
}

fn parse_time_simd(x: &[u8]) -> u32 {
    let result: u32;
    unsafe {
        let input = _mm_loadu_si64(x.as_ptr() as *const _);
        let input = _mm_sub_epi8(input, _mm_set1_epi8(b'0' as i8));
        let input = _mm_shuffle_epi8(input, _mm_set_epi8(7, 6, 4, 3, -1, -1, -1,  -1, 1, 0, -1, -1, -1,-1, -1, -1));
        let coeffs = _mm_set_epi8(1, 10, 1, 10, 1, 10, 0, 0, 1, 10, 0, 0, 0, 0, 0, 0);
        let prod = _mm_maddubs_epi16(coeffs, input);
        let prod2 = _mm_madd_epi16(prod, _mm_set_epi8(0, 1, 0, 60, 0, 0, 0, 0, 14, 16, 0, 0, 0, 0, 0, 0));
        let ms: u32 = transmute(_mm_extract_epi32::<1>(prod2));
        let h: u32 = transmute(_mm_extract_epi32::<3>(prod2));
        result = ms + h
    }
    result
}

fn parse_line_automata(line: &[u8]) -> Option<(IpAddr, NaiveTime)> {
    let ip = parse_ip_simd(&line[..16]);

    let first_space = memchr(b' ', &line[7..]).unwrap() + 7;
    let second_space = memchr(b' ', &line[(first_space + 3)..]).unwrap() + first_space + 3;
    let time_begin = memchr(b':', &line[second_space..]).unwrap() + second_space + 1;
    let time = parse_time_simd(&line[time_begin..time_begin + 8]);
    let time: NaiveTime = NaiveTime::from_num_seconds_from_midnight(time, 0);
    Some((ip, time))
}

#[cfg(test)]
mod tests {
    use chrono::NaiveTime;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::init_shuffle_table;

    #[test]
    fn test_parse_line_automata() {
        let line = br#"118.174.114.113 - - [25/May/2022:10:36:11 +0300] "GET / HTTP/1.1" 403 146 "-" "www.rusprofile.ru" "Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_2_1 like Mac OS X; da-dk) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148 Safari/6533.18.5" "84.57.120.161" - 0.000 - -"#;
        let (ip, time) = super::parse_line_automata(line).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(118, 174, 114, 113)));
        assert_eq!(time, NaiveTime::from_hms(10, 36, 11));
    }

    #[test]
    fn test_time_simd() {
        for h in 0..24 {
            for m in 0..60 {
                for s in 0..60 {
                    let time_str = format!("{:02}:{:02}:{:02}", h, m, s);
                    let time_simd = super::parse_time_simd(time_str.as_bytes());
                    assert_eq!(h*3600+m*60+s, time_simd);
                }
            }
        }
    }
}

fn main() -> io::Result<()> {
    init_shuffle_table();
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
            File::open(&config.log_file).expect("Failed to open log file"),
        ));
    }

    if !&config.log_regex.contains("(?P<ip>") {
        panic!("log_regex must contain (?P<ip> ... ) group for IP address");
    }
    if !&config.log_regex.contains("(?P<DT>") {
        panic!("log_regex must contain (?P<DT> ... ) group for datetime");
    }
    #[cfg(regex)]
    {
        let re = Regex::new(&config.log_regex).expect("Failed to compile regex");
    }
    #[cfg(regex_automata)]
    {
        let re_start = regex_automata::RegexBuilder::new()
            .anchored(true)
            .build(r#"\d+\.\d+\.\d+\.\d+"#)
            .expect("Failed to compile regex");

        let re_before_dt = regex_automata::RegexBuilder::new()
            .anchored(true)
            .build(r#" - [^ ]+ \[[^/]+/[^/]+/[^:]+:"#)
            .unwrap();

        let re_dt = regex_automata::RegexBuilder::new()
            .anchored(true)
            .build(r#"[^ ]+"#)
            .expect("Failed to compile regex");
    }

    let start = std::time::Instant::now();
    let mut ban_tickets = HashMap::<IpAddr, RingBanBuffer>::new();
    let mut line_count = 0;
    let mut dt_errors = 0;

    let reader = unsafe { MmapOptions::new().map(&File::open(&config.log_file)?)? };
    let len = reader.len();
    let mut start_pos = 0;
    loop {
        let next_line = memchr(b'\n', &reader[start_pos..len]);
        if next_line.is_none() {
            break;
        }
        let line = &reader[start_pos..start_pos + next_line.unwrap()];
        start_pos += next_line.unwrap() + 1;
        // if let Err(_) = line {
        //     eprintln!("Line read error, break!");
        //     break;
        // }
        // let line = line?;
        line_count += 1;
        #[cfg(regex_automata)]
        {
            let (ip_start, ip_end) = re_start.find(&line).unwrap();
            let (_, before_dt_start) = re_before_dt.find(&line[ip_end..]).unwrap();
            let (dt_start, dt_end) = re_dt.find(&line[ip_end + before_dt_start..]).unwrap();
            let raw_ip = String::from_utf8_lossy(&line[ip_start..ip_end]);
            let raw_dt = String::from_utf8_lossy(
                &line[before_dt_start + dt_start + ip_end..before_dt_start + dt_end + ip_end - 1],
            );
            // let captures = re.captures(&line);
            // if let Some(caps) = captures {
            let dt = NaiveTime::parse_from_str(&raw_dt, "%H:%M:%S");
            if let Err(_) = dt {
                eprintln!("Failed to parse date {}", raw_dt);
                dt_errors += 1;
                continue;
            }
            let dt = dt.unwrap();
            //parse ip into ipv4
            let ip = raw_ip.parse();
            if let Err(_) = ip {
                eprintln!("Failed to parse ip {}", raw_ip);
                continue;
            }
            let ip: IpAddr = ip.unwrap();
        }
        let (ip, dt) = parse_line_automata(&line).unwrap();
        let entry = ban_tickets.entry(ip);
        if let Entry::Occupied(mut entry) = entry {
            let mut buffer = entry.get_mut();
            if buffer.banned {
                continue;
            }
            let duration = buffer.add_query(dt);
            if let Some(dur) = duration {
                buffer.banned = true;
            }
        } else {
            let mut buffer = RingBanBuffer::new(config.requests);
            buffer.add_query(dt);
            entry.or_insert(buffer);
        }
    }

    let banned_ips: Vec<&IpAddr> = ban_tickets
        .iter()
        .filter(|(_, v)| v.banned)
        .map(|(k, _)| k)
        .collect();

    let elapsed = start.elapsed();
    eprintln!(
        "elapsed {} ms, {} lines parsed, {} datetime errors, {} lines/s, banned = {}/{}",
        elapsed.as_millis(),
        line_count,
        dt_errors,
        line_count as f64 / (elapsed.as_nanos() as f64 / 1_000_000_000.0),
        banned_ips.len(),
        ban_tickets.len()
    );

    for i in banned_ips {
        println!("{}", i);
    }
    Ok(())
}
