//! Functions for compressing/decompressing Kosinski-formatted data

use crate::io_traits::WriteOrdered;
use crate::bitstream::{IBitStream, OBitStream};
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use num_traits::PrimInt;
use std::convert::TryFrom;
use std::io::Cursor;

fn push<T: PrimInt, W: WriteOrdered<T>, O: ByteOrder>(
    bits: &mut OBitStream<T, O>,
    bit: bool,
    dst: &mut W,
    data: &mut Vec<u8>,
) {
    if bits.push(dst, bit) {
        dst.write_all(&data[..]).unwrap();
        data.clear();
    }
}

fn encode_internal<W: WriteBytesExt>(dst: &mut W, buffer: &[u8], slide_win: usize, rec_len: usize) {
    let mut bits = OBitStream::<u16, LittleEndian>::new();
    let mut data = Vec::new();
    bits.push(dst, true);

    let mut b_pointer = 1_usize;
    let mut i_offset = 0_usize;

    data.push(buffer[0]);

    loop {
        // Count and Offset
        let mut i_count: usize = std::cmp::min(rec_len, buffer.len() - b_pointer);
        let mut k: usize = 1;

        // TODO: THIS NEEDS TO BE A "DO WHILE" EQUIVALENT
        let i_min = b_pointer.saturating_sub(slide_win);
        for i in (i_min..b_pointer).rev() {
            // j = size of the longest matching subslice starting at i
            let mut j = 0_usize;
            while buffer[i + j] == buffer[b_pointer + j] {
                j += 1;
                if j >= i_count {
                    break;
                }
            }

            if j > k {
                k = j;
                i_offset = i;
            }
        }

        i_count = k;

        if i_count == 1 {
            push(&mut bits, true, dst, &mut data);
            data.push(buffer[b_pointer]);
        } else if i_count == 2 && b_pointer - i_offset > 256 {
            push(&mut bits, true, dst, &mut data);
            data.push(buffer[b_pointer]);
            i_count -= 1;
        } else if i_count < 6 && b_pointer - i_offset <= 256 {
            push(&mut bits, false, dst, &mut data);
            push(&mut bits, false, dst, &mut data);
            push(
                &mut bits,
                (((i_count - 2) >> 1) as u16 & 1) != 0,
                dst,
                &mut data,
            );
            push(&mut bits, ((i_count - 2) as u16 & 1) != 0, dst, &mut data);
            data.push(!(b_pointer - i_offset - 1) as u8);
        } else {
            push(&mut bits, false, dst, &mut data);
            push(&mut bits, true, dst, &mut data);

            let off = (b_pointer - i_offset - 1) as u16;
            let mut info = (!((off << 8) | (off >> 5)) & 0xFFF8) as u16;
            if i_count - 2 < 8 {
                info |= (i_count - 2) as u8 as u16;
                data.write_u16::<BigEndian>(info).unwrap();
            } else {
                data.write_u16::<BigEndian>(info).unwrap();
                data.push((i_count - 1) as u8);
            }
        }

        b_pointer += i_count;

        if b_pointer >= buffer.len() {
            break;
        }
    }

    push(&mut bits, false, dst, &mut data);
    push(&mut bits, true, dst, &mut data);

    if bits.waiting_bits() == 0 {
        data.push(0);
        data.push(0);
    }

    data.push(0x00);
    data.push(0xF0);
    data.push(0x00);

    bits.flush(dst, true);
    dst.write_all(&data[..]).unwrap();
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
            encode_internal(
                &mut dst,
                &input[input_idx..][..input_len],
                slide_win,
                rec_len,
            );

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
        encode_internal(&mut dst, input, slide_win, rec_len);
    }

    // Pad to even size.
    if dst.len() % 2 != 0 {
        dst.write_u8(0).unwrap();
    }

    Ok(dst)
}

fn decode_internal(src: &mut Cursor<Vec<u8>>, dst: &mut Vec<u8>, dec_bytes: &mut usize) {
    let mut bits = IBitStream::<u16, LittleEndian>::new(src);

    loop {
        if bits.pop(src) {
            dst.push(src.read_u8().unwrap());
            *dec_bytes += 1;
        } else {
            // Count and Offset
            let mut count;

            let offset = if bits.pop(src) {
                let lo = src.read_u8().unwrap();
                let hi = src.read_u8().unwrap();

                count = hi as usize & 0x07;

                if count == 0 {
                    count = src.read_u8().unwrap() as usize;
                    if count == 0 {
                        break;
                    } else if count == 1 {
                        continue;
                    }
                } else {
                    count += 1;
                }

                (((0xF8 & hi as isize) << 5) | lo as isize) - 0x2000
            } else {
                let lo = bits.pop(src);
                let hi = bits.pop(src);

                count = ((lo as usize) << 1) | ((hi as usize) + 1);

                src.read_u8().unwrap() as isize - 0x100
            };

            for _ in 0..=count {
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

    fn roundtrip(uncompressed: &str) {
        let uncompressed = parse_data(uncompressed);

        let compressed = encode_default(&uncompressed, false).unwrap();
        println!("Compressed: {:X?}", compressed);

        assert_eq!(decode(&compressed, false), Ok(uncompressed));
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
}
