use core::slice;
use memchr::memchr;
use memmap::MmapOptions;
use std::fs::File;
use std::io::{stdin, BufRead, BufReader};

pub fn create_buf_reader(filename: &str) -> Box<dyn BufRead> {
    let reader: Box<dyn BufRead>;
    if filename == "-" {
        reader = Box::new(BufReader::new(stdin()));
    } else {
        reader = Box::new(BufReader::new(
            File::open(filename).expect("Failed to open log file"),
        ));
    }
    reader
}

pub fn create_mmap_memchr_iter<'a, 'b>(filename: &'a str) -> impl Iterator<Item = &[u8]> + 'b {
    let reader = unsafe {
        MmapOptions::new()
            .map(&File::open(filename).unwrap())
            .unwrap()
    };
    let mut start_pos = 0;
    std::iter::from_fn(move || {
        let next_line = memchr(b'\n', &reader[start_pos..]);
        if next_line.is_none() {
            return None;
        }
        let line_len = next_line.unwrap();
        let line_start = start_pos;
        start_pos += line_len + 1;
        Some(unsafe { slice::from_raw_parts(reader.as_ptr().add(line_start), line_len) })
    })
}
