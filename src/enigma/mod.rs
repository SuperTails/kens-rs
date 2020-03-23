use crate::bitstream::{IBitStream, OBitStream};
use crate::io_traits::{ReadOrdered, WriteOrdered};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::io::Cursor;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct BaseFlagIo {
    n: u16,
}

impl BaseFlagIo {
    pub fn new(n: u16) -> BaseFlagIo {
        BaseFlagIo { n }
    }

    #[allow(clippy::identity_op)]
    pub fn read_bitfield<R: ReadOrdered<u16> + ?Sized>(
        self,
        src: &mut R,
        bits: &mut IBitStream<u16, BigEndian>,
    ) -> u16 {
        let mut flags = 0;
        if self.n & (1 << 4) != 0 {
            flags |= (bits.get(src) as u16) << 15;
        }
        if self.n & (1 << 3) != 0 {
            flags |= (bits.get(src) as u16) << 14;
        }
        if self.n & (1 << 2) != 0 {
            flags |= (bits.get(src) as u16) << 13;
        }
        if self.n & (1 << 1) != 0 {
            flags |= (bits.get(src) as u16) << 12;
        }
        if self.n & (1 << 0) != 0 {
            flags |= (bits.get(src) as u16) << 11;
        }
        flags
    }

    #[allow(clippy::identity_op)]
    pub fn write_bitfield<W: WriteOrdered<u16> + ?Sized>(
        self,
        dst: &mut W,
        bits: &mut OBitStream<u16, BigEndian>,
        flags: u16,
    ) {
        if self.n & (1 << 4) != 0 {
            bits.put(&mut *dst, (flags >> 15) & 1 != 0);
        }
        if self.n & (1 << 3) != 0 {
            bits.put(&mut *dst, (flags >> 14) & 1 != 0);
        }
        if self.n & (1 << 2) != 0 {
            bits.put(&mut *dst, (flags >> 13) & 1 != 0);
        }
        if self.n & (1 << 1) != 0 {
            bits.put(&mut *dst, (flags >> 12) & 1 != 0);
        }
        if self.n & (1 << 0) != 0 {
            bits.put(&mut *dst, (flags >> 11) & 1 != 0);
        }
    }
}

// This flushes (if needed) the contents of the inlined data buffer.
fn flush_buffer<W: WriteOrdered<u16> + ?Sized>(
    dst: &mut W,
    buf: &mut Vec<u16>,
    bits: &mut OBitStream<u16, BigEndian>,
    mask: BaseFlagIo,
    packet_length: u16,
) {
    if buf.is_empty() {
        return;
    }

    bits.write(dst, (0x70 | (buf.len() - 1) & 0xf) as u16, 7);
    for v in buf.iter().copied() {
        mask.write_bitfield(dst, bits, v);
        bits.write(dst, v & 0x7ff, packet_length as u32);
    }
    buf.clear();
}

fn encode_internal(src: &[u8]) -> Result<Vec<u8>, ()> {
    // To unpack source into 2-byte words.
    let mut unpack = Vec::<u16>::new();
    // Frequency map.
    let mut counts = HashMap::<u16, usize>::new();
    // Presence map.
    let mut elems = HashSet::<u16>::new();

    // Unpack source into array. Along the way, build frequency and presence maps.
    let mut maskval: u16 = 0;
    for c in src.chunks(2) {
        let v: u16 = BigEndian::read_u16(c);
        maskval |= v;
        *counts.entry(v).or_insert(0) += 1;
        elems.insert(v);
        unpack.push(v);
    }

    let mask = BaseFlagIo::new(maskval >> 11);
    let packet_length = ((maskval & 0x7ff) as f32).log2() as u16 + 1;

    // Find the most common 2-byte value.
    let common_value: u16 = *counts.iter().max_by_key(|(_, cnt)| *cnt).unwrap().0;

    // No longer needed.
    std::mem::drop(counts);

    // Find incrementing (not neccessarily contiguous) runs.
    // The original algorithm does this for all 65536 2-byte words, while
    // this version only checks the 2-byte words actually in the file.
    let mut runs = HashMap::<u16, usize>::new();
    for mut next in elems.iter().copied() {
        let val_cnt = runs.entry(next).or_insert(0);
        for it2 in unpack.iter().copied() {
            if it2 == next {
                next += 1;
                *val_cnt += 1;
            }
        }
    }
    // No longer needed.
    std::mem::drop(elems);

    // Find the starting 2-byte value with the longest incrementing run.
    let mut incrementing_value: u16 = *runs.iter().max_by_key(|(_, cnt)| *cnt).unwrap().0;

    // No longer needed.
    std::mem::drop(runs);

    let mut dst = Cursor::new(Vec::new());
    // Output header.
    dst.write_u8(packet_length as u8).unwrap();
    dst.write_u8((maskval >> 11) as u8).unwrap();
    dst.write_u16::<BigEndian>(incrementing_value).unwrap();
    dst.write_u16::<BigEndian>(common_value).unwrap();
    // Time now to compress the file.
    let mut bits = OBitStream::<u16, BigEndian>::new();
    let mut buf = Vec::<u16>::new();
    let mut pos: usize = 0;
    #[allow(clippy::identity_op)]
    while pos < unpack.len() {
        let v: u16 = unpack[pos];
        if v == incrementing_value {
            flush_buffer(&mut dst, &mut buf, &mut bits, mask, packet_length);
            let mut next: u16 = v + 1;

            let mut cnt: usize = 0;
            let mut i: usize = pos + 1;
            while i < unpack.len() && cnt < 0xF {
                if next != unpack[i] {
                    break;
                }

                next += 1;
                i += 1;
                cnt += 1;
            }
            bits.write(&mut dst, 0x00 | cnt as u16, 6);
            incrementing_value = next;
            pos += cnt;
        } else if v == common_value {
            flush_buffer(&mut dst, &mut buf, &mut bits, mask, packet_length);
            let next: u16 = v;
            let mut cnt: usize = 0;
            let mut i = pos + 1;
            while i < unpack.len() && cnt < 0xF {
                if next != unpack[i] {
                    break;
                }
                cnt += 1;
                i += 1;
            }
            bits.write(&mut dst, 0x10 | cnt as u16, 6);
            pos += cnt;
        } else {
            let mut next: u16 = unpack[pos + 1];
            let mut delta: i32 = next as i32 - v as i32;
            if pos + 1 < unpack.len()
                && next != incrementing_value
                && (delta == -1 || delta == 0 || delta == 1)
            {
                flush_buffer(&mut dst, &mut buf, &mut bits, mask, packet_length);
                let mut cnt: usize = 1;
                next = (next as i32 + delta).try_into().unwrap();
                let mut i = pos + 1;
                while i < unpack.len() && cnt < 0xF {
                    if next != unpack[i] || next == incrementing_value {
                        break;
                    }
                    next = (next as i32 + delta).try_into().unwrap();
                    cnt += 1;
                    i += 1;
                }

                if delta == -1 {
                    delta = 2;
                }

                delta = (delta | 4) << 4;
                bits.write(&mut dst, delta as u16 | cnt as u16, 7);
                mask.write_bitfield(&mut dst, &mut bits, v);
                bits.write(&mut dst, v & 0x7ff, packet_length as u32);
                pos += cnt;
            } else {
                if buf.len() >= 0xf {
                    flush_buffer(&mut dst, &mut buf, &mut bits, mask, packet_length);
                }

                buf.push(v);
            }
        }
        pos += 1;
    }

    flush_buffer(&mut dst, &mut buf, &mut bits, mask, packet_length);

    // Terminator.
    bits.write(&mut dst, 0x7f, 7);
    bits.flush(&mut dst, false);

    Ok(dst.into_inner())
}

pub fn encode(src: &[u8], padding: bool) -> Result<Vec<u8>, ()> {
    // Remove padding associated with S1 special stages in 80x80 block version.
    Ok(if padding && src.len() >= 0x3000 {
        let mut src_no_padding = Vec::new();
        let mut src_slice = src;
        src_slice = &src_slice[0x80 * 0x20..];
        for _ in 0..0x20 {
            src_slice = &src_slice[0x20..];
            src_no_padding.extend(&src_slice[..0x40]);
            src_slice = &src_slice[0x20..];
        }

        encode_internal(&src_no_padding)?
    } else {
        let mut dst = encode_internal(src)?;
        // Pad to even size.
        if dst.len() % 2 != 0 {
            dst.push(0);
        }

        dst
    })
}

// TODO: Use this instead
struct EnigmaData<'a> {
    packet_length: u8,
    get_mask: BaseFlagIo,
    incrementing_value: u16,
    common_value: u16,
    body: &'a [u8],
}

impl<'a> EnigmaData<'a> {
    pub fn new(mut data: &'a [u8]) -> Self {
        let data = &mut data;

        let packet_length: u8 = data.read_u8().unwrap();
        let get_mask = BaseFlagIo::new(data.read_u8().unwrap() as u16);
        let incrementing_value: u16 = data.read_u16::<BigEndian>().unwrap();
        let common_value: u16 = data.read_u16::<BigEndian>().unwrap();

        EnigmaData {
            packet_length,
            get_mask,
            incrementing_value,
            common_value,
            body: data,
        }
    }

    pub fn iter(&self) -> EnigmaDataIter<'a> {
        let mut body = self.body;
        let bits = IBitStream::new(&mut body);
        EnigmaDataIter {
            packet_length: self.packet_length,
            get_mask: self.get_mask,
            reached_end: false,
            bits,
            body,
        }
    }

    pub fn decompress<W: WriteBytesExt>(&self, dst: &mut W) {
        let mut incrementing_value = self.incrementing_value;

        for entry in self.iter() {
            match entry.type_bits {
                0b00 => {
                    // Copy in the incremental copy word repeat_count + 1 times, add 1 to the word after each copy
                    for _ in 0..entry.repeat_count + 1 {
                        dst.write_u16::<BigEndian>(incrementing_value).unwrap();
                        incrementing_value += 1;
                    }
                }
                0b01 => {
                    // Copy the literal copy word repeat_count + 1 times, add 1 to the word after each copy
                    for _ in 0..entry.repeat_count + 1 {
                        dst.write_u16::<BigEndian>(self.common_value).unwrap();
                    }
                }
                // Copy inline value repeat_count + 1 times
                0b100 |
                // Copy inline value repeat_count + 1 times, increment after each copy
                0b101 |
                // Copy inline value repeat_count + 1 times, decrement after each copy
                0b110 => {
                    let (flags, value) = entry.flags_and_value.unwrap();

                    let mut outv = value | flags;
                    for _ in 0..entry.repeat_count + 1 {
                        dst.write_u16::<BigEndian>(outv).unwrap();

                        if entry.type_bits == 0b101 {
                            outv += 1;
                        } else if entry.type_bits == 0b110 {
                            outv -= 1;
                        }
                    }
                }
                // If repeat count is 0xF, terminate decompression, otherwise
                // copy next inline value and repeat repeat_count + 1 times
                0b111 => {
                    let repeat_count = entry.repeat_count;
                    if repeat_count != 0xF {
                        todo!()
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

struct EnigmaDataIter<'a> {
    packet_length: u8,
    get_mask: BaseFlagIo,
    bits: IBitStream<u16, BigEndian>,
    body: &'a [u8],
    reached_end: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FormatEntry {
    type_bits: u8,
    repeat_count: u8,
    flags_and_value: Option<(u16, u16)>,
}

impl fmt::Display for FormatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_bits = if self.type_bits & 0b100 != 0 {
            format!("{:#b}", self.type_bits)
        } else {
            format!("0b{:0>2b}", self.type_bits)
        };
        write!(f, "{:>5}: {} repeats", type_bits, self.repeat_count)?;
        if let Some((flags, copy_value)) = self.flags_and_value {
            write!(f, "of {:#X} with flags {:#X}", copy_value, flags)?;
        }

        Ok(())
    }
}

impl<'a> Iterator for EnigmaDataIter<'a> {
    type Item = FormatEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reached_end {
            None
        } else {
            let type_head = self.bits.get(&mut self.body);
            let (type_body, type_body_len) = if type_head {
                // 2 more type bits
                (self.bits.read(&mut self.body, 2) as u8, 2)
            } else {
                (self.bits.get(&mut self.body) as u8, 1)
            };
            let type_bits = ((type_head as u8) << type_body_len) | type_body;

            let repeat_count = self.bits.read(&mut self.body, 4) as u8;

            let flags_and_value = if type_head {
                let flags = self.get_mask.read_bitfield(&mut self.body, &mut self.bits) as u16;
                let copy_value = self.bits.read(&mut self.body, self.packet_length as u32);
                Some((flags, copy_value))
            } else {
                None
            };

            if type_bits == 0b111 && repeat_count == 0xF {
                self.reached_end = true;
            }

            Some(FormatEntry {
                type_bits,
                repeat_count,
                flags_and_value,
            })
        }
    }
}

pub fn decode(src_slice: &[u8]) -> Vec<u8> {
    let mut src = Cursor::new(src_slice);
    let mut dst = Cursor::new(Vec::new());

    // Read header.
    let packet_length: u32 = src.read_u8().unwrap() as u32;
    let get_mask = BaseFlagIo::new(src.read_u8().unwrap() as u16);
    let mut incrementing_value: u16 = src.read_u16::<BigEndian>().unwrap();
    let common_value: u16 = src.read_u16::<BigEndian>().unwrap();

    let mut bits = IBitStream::<u16, BigEndian>::new(&mut src);

    loop {
        if bits.get(&mut src) {
            let mode = bits.read(&mut src, 2);
            match mode {
                // Copy inline value repeat_count + 1 times
                0 |
                // Copy inline value repeat_count + 1 times, increment value after each copy
                1 |
                // Copy inline value repeat_count + 1 times, decrement value after each copy
                2 => {
                    let repeat_count = bits.read(&mut src, 4) + 1;
                    let flags: u16 = get_mask.read_bitfield(&mut src, &mut bits);

                    let mut outv = bits.read(&mut src, packet_length) | flags;
                    for _ in 0..repeat_count {
                        dst.write_u16::<BigEndian>(outv).unwrap();

                        if mode == 1 {
                            outv += 1;
                        } else if mode == 2 {
                            outv -= 1;
                        }
                    }
                }
                // If repeat count is 0xF, terminate decompression, otherwise
                // copy next inline value and repeat repeat_count + 1 times
                3 => {
                    let repeat_count = bits.read(&mut src, 4);
                    // This marks decompression as being done.
                    if repeat_count == 0xF {
                        return dst.into_inner();
                    }

                    for _ in 0..=repeat_count {
                        let flags: u16 = get_mask.read_bitfield(&mut src, &mut bits);
                        let outv: u16 = bits.read(&mut src, packet_length);
                        dst.write_u16::<BigEndian>(outv | flags).unwrap();
                    }
                }
                _ => unreachable!(),
            }
        } else if !bits.get(&mut src) {
            // Copy in the incremental copy word repeat_count + 1 times, add 1 to the word after each copy
            let repeat_count = bits.read(&mut src, 4) + 1;
            for _ in 0..repeat_count {
                dst.write_u16::<BigEndian>(incrementing_value).unwrap();
                incrementing_value += 1;
            }
        } else {
            // Copy the literal copy word repeat_count + 1 times, add 1 to the word after each copy
            let repeat_count = bits.read(&mut src, 4) + 1;
            for _ in 0..repeat_count {
                dst.write_u16::<BigEndian>(common_value).unwrap();
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn example_test() {
        const EXAMPLE: &[u8] = &[
            0x07, 0x0C, 0x00, 0x00, 0x00, 0x10, 0x05, 0x3D, 0x11, 0x8F, 0xE0, 0x00,
        ];

        let result = decode(EXAMPLE);

        const EXPECTED: &[u8] = &[
            0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x10, 0x00, 0x10, 0x00, 0x10, 0x40, 0x18,
            0x40, 0x17, 0x40, 0x16, 0x40, 0x15, 0x40, 0x14, 0x40, 0x13, 0x40, 0x12, 0x40, 0x11,
            0x40, 0x10,
        ];

        assert_eq!(result, EXPECTED);
    }

    #[test]
    fn roundtrip() {
        const DATA: &[u8] = &[
            0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x10, 0x00, 0x10, 0x00, 0x10, 0x40, 0x18,
            0x40, 0x17, 0x40, 0x16, 0x40, 0x15, 0x40, 0x14, 0x40, 0x13, 0x40, 0x12, 0x40, 0x11,
            0x40, 0x10,
        ];

        let encoded = encode(DATA, false).unwrap();

        let result = decode(&encoded);

        assert_eq!(DATA, &result[..]);
    }

    /*const DATA: &[u8; 202] =
        include_bytes!("../../../megarust/roms/s2disasm/mappings/misc/2P Act Results.bin");

    #[test]
    fn decode_test() {
        println!("Input length: {}", DATA.len());
        let result = decode(DATA);
        eprintln!("Length: {}", result.len());

        for tile in result.chunks(0x20) {
            for row in 0..8 {
                for col in 0..8 {
                    let idx = row * 4 + col / 2;
                    let data = if col % 2 != 0 {
                        tile[idx] & 0xF
                    } else {
                        tile[idx] >> 4
                    };
                    
                    if data == 0 {
                        print!(".");
                    } else {
                        print!("{:X}", data);
                    }
                }
                println!();
            }
            println!();
        }

        panic!();
    }*/
}
