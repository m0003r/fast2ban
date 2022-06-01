use crate::{LineParser, ParseError, ParseResult};
use memchr::memchr;
use std::arch::x86_64::*;
use std::mem::transmute;
use std::net::{IpAddr, Ipv4Addr};

pub(crate) struct SimdParser {
    shuffle_table: Box<[__m128i; 65536]>,
}

impl SimdParser {
    pub fn new() -> SimdParser {
        let mut shuffle_table = Box::new([unsafe { _mm_setzero_si128() }; 65536]);
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
                                    &mut shuffle_table[mask],
                                    _mm_loadu_si128(&shuf as *const i8 as *const __m128i),
                                );
                            }
                        }
                    }
                }
            }
        }

        SimdParser { shuffle_table }
    }
}

impl SimdParser {
    fn parse_ip_simd(&self, x: &[u8]) -> IpAddr {
        let result: u32;
        unsafe {
            let input = _mm_lddqu_si128(x.as_ptr() as *const __m128i); //"192.167.1.3"
            let input = _mm_sub_epi8(input, _mm_set1_epi8(b'0' as i8)); //1 9 2 254 1 6 7 254 1 254 3 208 245 0 8 40
            let cmp = input; //...X...X.X.XX...  (signs)
            let mask = _mm_movemask_epi8(cmp); //6792 - magic index
            let shuf = self.shuffle_table[mask as usize]; //10 -1 -1 -1 8 -1 -1 -1 6 5 4 -1 2 1 0 -1
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
            let ms: u32 = transmute(_mm_extract_epi32::<1>(prod2));
            let h: u32 = transmute(_mm_extract_epi32::<3>(prod2));
            ms + h
        }
    }
}
impl LineParser<&[u8]> for SimdParser {
    #[inline(always)]
    fn parse_line(&self, line: &[u8]) -> Result<ParseResult, ParseError> {
        let ip = self.parse_ip_simd(&line[..16]);

        let first_space = memchr(b' ', &line[7..]).unwrap() + 7;
        let second_space = memchr(b' ', &line[(first_space + 3)..]).unwrap() + first_space + 3;
        let time_begin = memchr(b':', &line[second_space..]).unwrap() + second_space + 1;
        let time = Self::parse_time_simd(&line[time_begin..time_begin + 8]);
        Ok(ParseResult {
            ip,
            timestamp: time as i64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn test_simd_parser() {
        let parser = SimdParser::new();
        let mut lines = get_lines("test_data/access.log");
        let mut results = Vec::new();
        while let Some(line) = lines.next() {
            let result = parser.parse_line(line.as_bytes()).unwrap();
            results.push(result);
        }
        assert_eq!(results.len(), 100);
    }
}
