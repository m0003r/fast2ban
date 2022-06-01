use chrono::*;
use regex::Regex;
use std::arch::x86_64::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::str::from_utf8_unchecked;
use memchr::memchr;

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
        let timestamp = DateTime::parse_from_str(&caps["DT"], &self.date_format)
            .ok()?
            .timestamp();
        let ip: IpAddr = caps["ip"].parse().ok()?;
        Some(ParseResult { ip, timestamp })
    }
}

fn parse_line_automata(line: &[u8], date_format: &str) -> Option<ParseResult> {
    let mut iter = line.iter().enumerate();
    let ip_end = iter.position(|(_, &c)| c == b' ')?;

    let ip_str = unsafe { from_utf8_unchecked(&line[..ip_end]) };
    let ip: IpAddr = ip_str.parse().ok()?;

    let mut iter = iter
        .skip(3)
        .skip_while(|&(_, &c)| c != b' ')
        .skip_while(|&(_, &c)| c != b'[');

    let (date_start, _) = iter.next()?;
    let date_end = iter.position(|(_, &c)| c == b']')?;

    let date = unsafe { from_utf8_unchecked(&line[date_start + 1..date_start + date_end + 1]) };

    let timestamp = DateTime::parse_from_str(date, date_format)
        .ok()?
        .timestamp();

    Some(ParseResult { ip, timestamp })
}

fn parse_line_automata_time_only(line: &[u8], time_format: &str) -> Option<ParseResult> {
    let mut iter = line.iter().enumerate();
    let ip_end = iter.position(|(_, &c)| c == b' ')?;

    let ip_str = unsafe { from_utf8_unchecked(&line[..ip_end]) };
    let ip: IpAddr = ip_str.parse().ok()?;

    let mut iter = iter
        .skip(3)
        .skip_while(|&(_, &c)| c != b' ')
        .skip_while(|&(_, &c)| c != b':');

    let (date_start, _) = iter.next()?;

    let time = unsafe { from_utf8_unchecked(&line[date_start + 1..date_start + 9]) };

    let timestamp = NaiveTime::parse_from_str(time, time_format)
        .ok()?
        .num_seconds_from_midnight() as i64;

    Some(ParseResult { ip, timestamp })
}

fn parse_line_v2(line: &[u8]) -> Option<ParseResult> {
    let mut ip = 0u32;
    let mut cur_grp = 0u32;
    let mut timestamp = 0i64;
    let mut cur_time = 0i64;

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
            timestamp = timestamp * 60 + cur_time;
            cur_time = 0;
            continue;
        }
        if *c == b' ' {
            break;
        }
        cur_time = cur_time * 10 + (*c - b'0') as i64;
    }
    timestamp = timestamp * 60 + cur_time;
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::from(ip));
    Some(ParseResult { ip, timestamp })
}

static mut SHUFFLE_TABLE: [__m128i; 65536] = [unsafe { std::mem::transmute(0_i128) }; 65536];

fn parse_ip_simd(addr: &[u8]) -> IpAddr {
    let result: u32;
    unsafe {
        let input = _mm_lddqu_si128(addr.as_ptr() as *const __m128i);
        let input = _mm_sub_epi8(input, _mm_set1_epi8(b'0' as i8));
        let cmp = input;
        let mask = _mm_movemask_epi8(cmp);
        let shuf = SHUFFLE_TABLE[mask as usize];
        let arr = _mm_shuffle_epi8(input, shuf);
        let coeffs = _mm_set_epi8(0, 100, 10, 1, 0, 100, 10, 1, 0, 100, 10, 1, 0, 100, 10, 1);
        let prod = _mm_maddubs_epi16(coeffs, arr);
        let prod = _mm_hadd_epi16(prod, prod);
        let imm = _mm_set_epi8(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6, 4, 2, 0);
        let prod = _mm_shuffle_epi8(prod, imm);
        result = std::mem::transmute(_mm_extract_epi32::<0>(prod))
    }
    IpAddr::V4(Ipv4Addr::from(result))
}

fn init_shuffle_table() {
    for len0 in 1..4 {
        for len1 in 1..4 {
            for len2 in 1..4 {
                for len3 in 1..4 {
                    let slen = len0 + len1 + len2 + len3 + 4;
                    let lens = [&len0, &len1, &len2, &len3];
                    let rem = 16 - slen;
                    for rmask in 0..(1 << rem) {
                        let mut mask = 0;
                        let mut shuf: [i8; 16] = [-1; 16];
                        let mut pos = 0;
                        for i in 0..4 {
                            for j in 0..*lens[i] {
                                shuf[((3 - i) * 4 + (lens[i] - 1 - j))] = pos;
                                pos += 1;
                            }
                            mask ^= (1) << pos;
                            pos += 1;
                        }
                        mask ^= rmask << slen;
                        unsafe {
                            _mm_store_si128(
                                &mut SHUFFLE_TABLE[mask],
                                _mm_loadu_si128(&shuf as *const i8 as *const __m128i),
                            );
                        }
                    }
                }
            }
        }
    }
}

fn parse_time_simd(x: &[u8]) -> u32 {
    unsafe {
        let input = _mm_loadu_si64(x.as_ptr() as *const _);
        let input = _mm_sub_epi8(input, _mm_set1_epi8(b'0' as i8));
        let input = _mm_shuffle_epi8(
            input,
            _mm_set_epi8(7, 6, 4, 3, -1, -1, -1, -1, 1, 0, -1, -1, -1, -1, -1, -1),
        );
        let coeffs = _mm_set_epi8(1, 10, 1, 10, 1, 10, 0, 0, 1, 10, 0, 0, 0, 0, 0, 0);
        let prod = _mm_maddubs_epi16(coeffs, input);
        let prod2 = _mm_madd_epi16(
            prod,
            _mm_set_epi8(0, 1, 0, 60, 0, 0, 0, 0, 14, 16, 0, 0, 0, 0, 0, 0),
        );
        let ms: u32 = std::mem::transmute(_mm_extract_epi32::<1>(prod2));
        let h: u32 = std::mem::transmute(_mm_extract_epi32::<3>(prod2));
        ms + h
    }
}

fn parse_line_simd(line: &[u8]) -> Option<ParseResult> {
    let ip = parse_ip_simd(&line[..16]);

    let first_space = memchr(b' ', &line[7..])? + 7;
    let second_space = memchr(b' ', &line[(first_space + 3)..])? + first_space + 3;
    let time_begin = memchr(b':', &line[second_space..])? + second_space + 1;
    let timestamp = parse_time_simd(&line[time_begin..time_begin + 8]) as i64;

    Some(ParseResult { ip, timestamp })
}

fn main() {
    init_shuffle_table();

    let reader = BufReader::new(File::open("nginx.log").unwrap());

    let mut requests: HashMap<IpAddr, (RingBanBuffer, bool)> = HashMap::new();

    let mut line_count = 0;
    let start = std::time::Instant::now();
    for line in reader.split(b'\n') {
        line_count += 1;
        if let Some(ParseResult { ip, timestamp }) = line.ok().and_then(|l| parse_line_simd(&l)) {
            let entry = requests
                .entry(ip)
                .or_insert((RingBanBuffer::new(30), false));
            if let Some(delta) = entry.0.add_query(timestamp) {
                if delta < 30 {
                    entry.1 = true;
                }
            };
        }
    }

    let elapsed = start.elapsed();

    let banned_ips: Vec<&IpAddr> = requests
        .iter()
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
