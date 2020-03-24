//! Functions for compressing/decompressing Kosinski-formatted data

use crate::bitstream::{IBitStream, OBitStream};
use crate::io_traits::WriteOrdered;
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use num_traits::PrimInt;
use std::convert::TryFrom;
use std::io::Cursor;

fn push<T: PrimInt, W: WriteOrdered<T> + ?Sized, O: ByteOrder>(
    bit: bool,
    bits: &mut OBitStream<T, O>,
    dst: &mut W,
    data: &mut Vec<u8>,
) {
    if bits.push(dst, bit) {
        dst.write_all(&data[..]).unwrap();
        data.clear();
    }
}

fn encode_internal(src: &[u8], sliding_window_len: usize, rec_len: usize) -> Vec<u8> {
    assert!(rec_len < 256 + 2);

    let mut written = Vec::new();

    // The description field, aka field A, which is two bytes long
    let mut bits = OBitStream::<u16, LittleEndian>::new();
    // The data field, aka field B, which follows the description field
    let mut data = Vec::new();

    // First byte *has* to be uncompressed, because otherwise
    // we would have nothing to dictionary match against
    bits.push(&mut written, true);
    data.push(src[0]);

    let mut src_idx: usize = 1;

    // The index of the last match found
    let mut match_idx: Option<usize> = None;

    #[allow(clippy::identity_op)]
    loop {
        // The farthest index back we are going to look for dictionary matches
        let i_min = src_idx.saturating_sub(sliding_window_len);

        // The maximum length of a dictionary match (obviously limited by the amount of data left as well)
        let max_match_len = std::cmp::min(rec_len, src.len() - src_idx);

        // TODO: Why does this start at 1?
        let mut largest_match_len = 1;

        // Search starting as far back as possible
        for i in (i_min..src_idx).rev() {
            let mut match_len = 0_usize;
            let history = &src[i..];
            let current = &src[src_idx..];
            while history[match_len] == current[match_len] {
                match_len += 1;
                if match_len >= max_match_len {
                    break;
                }
            }
            let match_len = match_len;

            if match_len > largest_match_len {
                match_idx = Some(i);
                largest_match_len = match_len;
            }
        }

        // Ideally, we should be able to just compress the whole match!
        let mut compressed_count = largest_match_len;

        if compressed_count == 1 {
            // Uncompressed data
            // There's no point in a dictionary match of length 1
            push(true, &mut bits, &mut written, &mut data);
            data.push(src[src_idx]);
        } else if compressed_count == 2 /*|| (src_idx - match_idx.unwrap() > 256 && compressed_count*/ {
            // TODO: Determine what the other condition is for

            // Uncompressed data
            // Again, no point in a dictionary match of length 2
            push(true, &mut bits, &mut written, &mut data);
            data.push(src[src_idx]);

            compressed_count = 1;
        } else if compressed_count < 6 && src_idx - match_idx.unwrap() <= 256 {
            // Inline dictionary match
            // Inline matches can only have at most 6 bytes, and an offset of -256 or less

            // This field is offset by 2
            let count = compressed_count - 2;

            push(false, &mut bits, &mut written, &mut data);
            push(false, &mut bits, &mut written, &mut data);
            push(count & (1 << 1) != 0, &mut bits, &mut written, &mut data);
            push(count & (1 << 0) != 0, &mut bits, &mut written, &mut data);

            data.push(!(src_idx - match_idx.unwrap() - 1) as u8);
        } else {
            // Full dictionary match

            // This field is offset by 2
            let count = compressed_count - 2;

            let offset = !(src_idx - match_idx.unwrap() - 1) as u16;
            let offset_lo = offset as u8;
            let offset_hi = (offset >> 8) as u8;

            push(false, &mut bits, &mut written, &mut data);
            push(true,  &mut bits, &mut written, &mut data);

            data.write_u8(offset_lo).unwrap();

            if count < 8 {
                // Use the two byte format
                data.write_u8((offset_hi << 3) | count as u8).unwrap();
            } else {
                data.write_u8(offset_hi << 3).unwrap();
                data.write_u8(count as u8).unwrap();
            }
        }

        // We've finished with these bytes
        src_idx += compressed_count;

        if src_idx >= src.len() {
            break;
        }
    }

    push(false, &mut bits, &mut written, &mut data);
    push(true, &mut bits, &mut written, &mut data);

    // The Kosinski algorithm will greedily
    // read another description field, so we need to give it one
    if bits.waiting_bits() == 0 {
        data.push(0);
        data.push(0);
    }

    // TODO: Isn't this supposed to be the end-of-compression sequence?
    data.push(0x00);
    data.push(0xF0);
    data.push(0x00);

    // TODO: Why true?
    bits.flush(&mut written, true);

    written.extend_from_slice(&data);

    written
}

pub const DEFAULT_SLIDE_WIN: usize = 8192;
pub const DEFAULT_REC_LEN: usize = 256;
pub const DEFAULT_MODULE_SIZE: usize = 0x1000;

/// Convenience function to call `encode` with the default settings
pub fn encode_default(input: &[u8], moduled: bool) -> Result<Vec<u8>, ()> {
    encode(
        input,
        DEFAULT_SLIDE_WIN,
        DEFAULT_REC_LEN,
        moduled,
        DEFAULT_MODULE_SIZE,
    )
}

/// Encodes raw data into the Kosinski format
///
/// If `moduled` is true then the data will be interpreted
/// as being in the Kosinski Moduled format, as used in
/// Sonic 3 and Knuckles
pub fn encode(
    input: &[u8],
    slide_win: usize,
    rec_len: usize,
    moduled: bool,
    module_size: usize,
) -> Result<Vec<u8>, ()> {
    let mut dst = Vec::new();

    if moduled {
        if input.len() > 65535 {
            // Decompressed size would fill RAM or VRAM.
            return Err(());
        }

        let full_size: usize = input.len();

        let mut comp_bytes: usize = 0;

        let mut input_idx = 0;
        let mut input_len = input.len().min(module_size);

        dst.write_u16::<BigEndian>(full_size as u16).unwrap();

        loop {
            let encoded = encode_internal(
                &input[input_idx..][..input_len],
                slide_win,
                rec_len,
            );

            dst.extend_from_slice(&encoded);

            comp_bytes += input_len;
            input_idx += input_len;

            if comp_bytes >= full_size {
                break;
            }

            // Padding between modules
            let padding_end = (((dst.len() - 2) + 0xf) & !0xf) + 2;
            let n = padding_end - dst.len();

            for _ in 0..n {
                dst.write_u8(0).unwrap();
            }

            input_len = std::cmp::min(module_size, full_size - comp_bytes);
        }
    } else {
        let encoded = encode_internal(input, slide_win, rec_len);
        dst.extend_from_slice(&encoded);
    }

    // Pad to even size.
    if dst.len() % 2 != 0 {
        dst.write_u8(0).unwrap();
    }

    Ok(dst)
}

fn decode_internal(src: &mut Cursor<Vec<u8>>, dst: &mut Vec<u8>, dec_bytes: &mut usize) {
    let mut bits = IBitStream::<u16, LittleEndian>::new();
    bits.check_buffer(src);

    loop {
        if bits.pop(src) {
            bits.check_buffer(src);

            dst.push(src.read_u8().unwrap());
            *dec_bytes += 1;
        } else {
            // Count and Offset
            let (count, offset) = if bits.pop(src) {
                // Full dictionary match

                bits.check_buffer(src);

                let lo = src.read_u8().unwrap();
                let hi = src.read_u8().unwrap();

                let offset = (((0xF8 & hi as isize) << 5) | lo as isize) - 0x2000;

                let count = hi as usize & 0x07;

                let count = if count == 0 {
                    // Three byte form
                    let tmp = src.read_u8().unwrap() as usize;
                    if tmp == 0 {
                        break;
                    } else if tmp == 1 {
                        continue;
                    }

                    tmp
                } else {
                    count
                };

                (count, offset)
            } else {
                // Inline dictionary match

                // Count 
                let hi = bits.pop(src);
                let lo = bits.pop(src);
                bits.check_buffer(src);
                
                let count = ((hi as usize) << 1) | lo as usize;
                let offset = src.read_u8().unwrap() as isize - 0x100;

                (count, offset)
            };

            for _ in 0..count + 2 {
                let idx = usize::try_from(offset + dst.len() as isize)
                    .unwrap_or_else(|_| panic!("Offset too large: {}", offset));
                let byte = dst[idx];
                dst.push(byte);
            }

            *dec_bytes += count + 1;
        }
    }
}

/// Decompresses data that has been Kosinski encoded
///
/// If `moduled` is true then the data will be interpreted
/// as being in the Kosinski Moduled format, as used in
/// Sonic 3 and Knuckles
pub fn decode(src: &[u8], moduled: bool) -> Result<Vec<u8>, ()> {
    let mut dec_bytes = 0_usize;

    let mut src = src.to_vec();
    // Pad to even length, for safety.
    if src.len() % 2 != 0 {
        src.push(0x00);
    }
    let mut src = Cursor::new(src);

    let mut dst = Vec::new();
    if moduled {
        let full_size: usize = src.read_u16::<BigEndian>().unwrap() as usize;
        loop {
            decode_internal(&mut src, &mut dst, &mut dec_bytes);
            if dec_bytes >= full_size {
                break;
            }

            // Skip padding between modules
            let padding_end = (((src.position() - 2) + 0xf) & !0xf) + 2;
            src.set_position(padding_end);
        }
    } else {
        decode_internal(&mut src, &mut dst, &mut dec_bytes);
    }

    Ok(dst)
}

#[cfg(test)]
mod test {
    use super::*;

    fn parse_data(s: &str) -> Vec<u8> {
        s.split(' ')
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }

    fn decompress_test(compressed: &str, uncompressed: &str) {
        let compressed = parse_data(compressed);
        let uncompressed = parse_data(uncompressed);

        assert_eq!(decode(&compressed, false), Ok(uncompressed));
    }

    fn roundtrip2(uncompressed: &[u8], moduled: bool) {
        let compressed = encode_default(&uncompressed, moduled).unwrap();
        print!("Compressed:\n[");
        for b in compressed.iter() {
            print!("{:02X}, ", b);
        }
        println!("]");

        let result = decode(&compressed, moduled).unwrap();

        if result != &uncompressed[..] {
            eprint!("\nExpected:\n[");
            for b in uncompressed.iter() {
                eprint!("{:02X}, ", b);
            }
            eprint!("]\nActual:\n[");
            for b in result.iter() {
                eprint!("{:02X}, ", b);
            }
            eprintln!("]\n");
        }

        assert_eq!(decode(&compressed, false).unwrap(), &uncompressed[..]);
    }

    fn roundtrip(uncompressed: &str) {
        roundtrip2(&parse_data(uncompressed), false);
    }

    #[test]
    fn uncompressed_test() {
        decompress_test(
            "FF 5F 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 00 F0 00",
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C",
        )
    }

    #[test]
    fn uncompressed_roundtrip() {
        roundtrip("00 01 02 03 04 05 06 07 08 09 0A 0B 0C")
    }

    #[test]
    fn inline_test() {
        decompress_test("51 00 25 FF 00 F0 00", "25 25 25 25")
    }

    #[test]
    fn final_decompression() {
        decompress_test(
            "FF 3F 54 3B C4 44 54 33 33 5B 2D 5C 44 5C C4 C5 FC 15 FE C3 44 78 88 98 44 30 FF FF 00 F8 00",
            "54 3B C4 44 54 33 33 5B 2D 5C 44 5C C4 C5 C4 C5 C3 44 78 88 98 44 30 30 30 30 30 30 30 30 30 30",
        );
    }

    #[test]
    fn final_roundtrip() {
        roundtrip(
            "54 3B C4 44 54 33 33 5B 2D 5C 44 5C C4 C5 C4 C5 C3 44 78 88 98 44 30 30 30 30 30 30 30 30 30 30",
        )
    }

    #[test]
    fn fuzz_case_0() {
        roundtrip2(&[
            0x60, 0xe0, 0xe0, 0xe0, 0xe0, 0xe0, 0xe0, 0x0e, 0x20, 0x80, 0x00, 0x00, 0x00, 0xe0,
            0xe0, 0xe0, 0x00, 0x84, 0x00, 0x00, 0xe0, 0xe0, 0xfa, 0xe0, 0x90, 0x00, 0x00, 0x23,
            0xe0, 0x67,
        ], false);
    }
}