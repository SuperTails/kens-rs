use crate::bitstream::{IBitStream, OBitStream};
use crate::io_traits::{ReadOrdered, WriteOrdered};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::convert::TryInto;
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

fn flush_buffer(out: &mut EnigmaData, buffer: &mut Vec<u16>, packet_length: u8) {
    if buffer.is_empty() {
        return;
    }

    assert!(buffer.len() <= 0xF);

    let flags_and_value = std::mem::take(buffer)
        .into_iter()
        .map(|v| {
            let value_mask = (1 << packet_length) - 1;
            let flags = !value_mask & v;
            let value = value_mask & v;
            (flags, value)
        })
        .collect::<Vec<(u16, u16)>>();

    let entry = FormatEntry {
        type_bits: 0b111,
        repeat_count: flags_and_value.len() as u8 - 1,
        flags_and_value,
    };

    out.body.push(entry);
}

fn encode_internal(src: &[u8]) -> EnigmaData {
    // To unpack source into 2-byte words.
    let mut unpack = Vec::<u16>::new();
    // Frequency map.
    let mut counts = HashMap::<u16, usize>::new();

    // Unpack source into array. Along the way, build frequency and presence maps.
    let mut maskval: u16 = 0;
    for c in src.chunks(2) {
        let v: u16 = BigEndian::read_u16(c);
        maskval |= v;
        *counts.entry(v).or_insert(0) += 1;
        unpack.push(v);
    }

    let packet_length = ((maskval & 0x7ff) as f32).log2() as u8 + 1;

    // Find the most common 2-byte value.
    let common_value: u16 = *counts.iter().max_by_key(|(_, cnt)| *cnt).unwrap().0;

    // Find incrementing (not neccessarily contiguous) runs.
    // The original algorithm does this for all 65536 2-byte words, while
    // this version only checks the 2-byte words actually in the file.
    let mut runs = HashMap::<u16, usize>::new();
    for mut next in counts.keys().copied() {
        let val_cnt = runs.entry(next).or_insert(0);
        for it2 in unpack.iter().copied() {
            if it2 == next {
                next += 1;
                *val_cnt += 1;
            }
        }
    }

    // Find the starting 2-byte value with the longest incrementing run.
    let mut incrementing_value: u16 = *runs.iter().max_by_key(|(_, cnt)| *cnt).unwrap().0;

    // No longer needed.
    std::mem::drop(runs);

    let mut result = EnigmaData {
        packet_length,
        get_mask: BaseFlagIo::new(maskval >> 11),
        common_value,
        incrementing_value,
        body: Vec::new(),
    };

    let mut buf = Vec::new();

    let mut pos: usize = 0;
    #[allow(clippy::identity_op)]
    while pos < unpack.len() {
        let v: u16 = unpack[pos];
        if v == incrementing_value {
            flush_buffer(&mut result, &mut buf, packet_length);

            let mut next: u16 = v + 1;

            let mut repeat_count: u8 = 0;
            let mut i: usize = pos + 1;
            while i < unpack.len() && repeat_count < 0xF {
                if next != unpack[i] {
                    break;
                }

                next += 1;
                i += 1;
                repeat_count += 1;
            }

            result.body.push(FormatEntry {
                type_bits: 0b00,
                flags_and_value: Vec::new(),
                repeat_count,
            });

            incrementing_value = next;
            pos += repeat_count as usize;
        } else if v == common_value {
            flush_buffer(&mut result, &mut buf, packet_length);

            let next: u16 = v;
            let mut repeat_count: u8 = 0;
            let mut i = pos + 1;
            while i < unpack.len() && repeat_count < 0xF {
                if next != unpack[i] {
                    break;
                }
                repeat_count += 1;
                i += 1;
            }

            result.body.push(FormatEntry {
                type_bits: 0b01,
                flags_and_value: Vec::new(),
                repeat_count,
            });

            pos += repeat_count as usize;
        } else if pos + 1 < unpack.len() && unpack[pos + 1] != incrementing_value {
            flush_buffer(&mut result, &mut buf, packet_length);

            let delta: i32 = unpack[pos + 1] as i32 - v as i32;

            if delta == -1 || delta == 0 || delta == 1 {
                let mut repeat_count = 1_u8;

                while pos + (repeat_count as usize) < unpack.len() && repeat_count < 0xF {
                    let expected: u16 = (unpack[pos] as i32 + delta * repeat_count as i32).try_into().unwrap();
                    if expected != unpack[pos + repeat_count as usize] {
                        break;
                    }

                    repeat_count += 1;
                }

                repeat_count -= 1;

                let delta_bits = if delta == -1 {
                    2
                } else {
                    delta as u8
                };

                let value_mask = (1 << packet_length) - 1;
                let value = value_mask & v;
                let flags = !value_mask & v;

                result.body.push(FormatEntry {
                    type_bits: 0b100 | delta_bits,
                    flags_and_value: vec![(flags, value)],
                    repeat_count,
                });

                pos += repeat_count as usize;
            } else {
                if buf.len() == 0xF {
                    flush_buffer(&mut result, &mut buf, packet_length);
                }

                buf.push(v);
            }
        } else {
            if buf.len() == 0xF {
                flush_buffer(&mut result, &mut buf, packet_length);
            }

            buf.push(v);
        }
        pos += 1;
    }

    flush_buffer(&mut result, &mut buf, packet_length);

    // Terminator
    result.body.push(FormatEntry {
        type_bits: 0b111,
        repeat_count: 0xF,
        flags_and_value: Vec::new(),
    });

    result
}

pub fn encode(src: &[u8], padding: bool) -> Result<Vec<u8>, ()> {
    let mut src_no_padding = Vec::new();

    // Remove padding associated with S1 special stages in 80x80 block version.
    let src = if padding && src.len() >= 0x3000 {
        let mut src_slice = src;
        src_slice = &src_slice[0x80 * 0x20..];
        for _ in 0..0x20 {
            src_slice = &src_slice[0x20..];
            src_no_padding.extend(&src_slice[..0x40]);
            src_slice = &src_slice[0x20..];
        }

        &src_no_padding[..]
    } else {
        src
    };

    Ok(encode_internal(src).serialize())
}

// TODO: Use this instead
struct EnigmaData {
    packet_length: u8,
    get_mask: BaseFlagIo,
    incrementing_value: u16,
    common_value: u16,
    body: Vec<FormatEntry>,
}

impl EnigmaData {
    pub fn deserialize(mut data: &[u8]) -> Self {
        let mut data = &mut data;

        let packet_length: u8 = data.read_u8().unwrap();
        let get_mask = BaseFlagIo::new(data.read_u8().unwrap() as u16);
        let incrementing_value: u16 = data.read_u16::<BigEndian>().unwrap();
        let common_value: u16 = data.read_u16::<BigEndian>().unwrap();

        let bits = IBitStream::new(&mut data);
        let iter = EnigmaDataIter {
            packet_length,
            get_mask,
            reached_end: false,
            bits,
            body: data,
        };

        let body = iter.collect::<Vec<_>>();

        EnigmaData {
            packet_length,
            get_mask,
            incrementing_value,
            common_value,
            body,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut dst = Vec::new();

        dst.write_u8(self.packet_length).unwrap();
        dst.write_u8(self.get_mask.n as u8).unwrap();
        dst.write_u16::<BigEndian>(self.incrementing_value).unwrap();
        dst.write_u16::<BigEndian>(self.common_value).unwrap();

        let mut bits = OBitStream::<u16, BigEndian>::new();

        for entry in self.body.iter() {
            let type_bit_count = if entry.type_bits & 0b100 != 0 { 3 } else { 2 };
            bits.write(&mut dst, entry.type_bits as u16, type_bit_count);
            bits.write(&mut dst, entry.repeat_count as u16, 4);
            for &(flags, value) in entry.flags_and_value.iter() {
                self.get_mask.write_bitfield(&mut dst, &mut bits, flags);
                bits.write(&mut dst, value, self.packet_length as u32);
            }
        }

        bits.flush(&mut dst, false);

        if dst.len() % 2 != 0 {
            dst.push(0);
        }

        dst
    }

    pub fn decompress<W: WriteBytesExt>(&self, dst: &mut W) {
        let mut incrementing_value = self.incrementing_value;

        for entry in self.body.iter() {
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
                    let (flags, value) = entry.flags_and_value[0];

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
                        for (flags, value) in entry.flags_and_value.iter() {
                            dst.write_u16::<BigEndian>(flags | value).unwrap();
                        }
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FormatEntry {
    type_bits: u8,
    repeat_count: u8,
    flags_and_value: Vec<(u16, u16)>,
}

impl fmt::Display for FormatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_bits = if self.type_bits & 0b100 != 0 {
            format!("{:#b}", self.type_bits)
        } else {
            format!("0b{:0>2b}", self.type_bits)
        };
        write!(f, "{:>5}: ", type_bits)?;
        if self.type_bits == 0b111 && self.repeat_count == 15 {
            write!(f, "Termination sequence")?;
        } else {
            write!(f, "{} repeats", self.repeat_count)?;
            if !self.flags_and_value.is_empty() {
                let inner: String = self.flags_and_value.iter()
                    .map(|(flags, copy_value)| {
                        format!("({:#X} with flags {:#X})", copy_value, flags)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");

                write!(f, " of [{}]", inner)?;
            }
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
            // Special case to prevent a crash trying to read more bytes too eagerly
            if self.bits.byte_buffer() == 0x7F {
                self.reached_end = true;

                return Some(FormatEntry {
                    type_bits: 0b111,
                    repeat_count: 0xF,
                    flags_and_value: Vec::new(),
                })
            }

            let type_head = self.bits.get(&mut self.body);
            let (type_body, type_body_len) = if type_head {
                // 2 more type bits
                (self.bits.read(&mut self.body, 2) as u8, 2)
            } else {
                (self.bits.get(&mut self.body) as u8, 1)
            };
            let type_bits = ((type_head as u8) << type_body_len) | type_body;

            let repeat_count = self.bits.read(&mut self.body, 4) as u8;

            let fv_count = if type_bits == 0b111  {
                if repeat_count == 0xF { 0 } else { repeat_count }
            } else if type_head {
                1
            } else {
                0
            };

            let flags_and_value = (0..fv_count).map(|_| {
                let flags = self.get_mask.read_bitfield(&mut self.body, &mut self.bits) as u16;
                let copy_value = self.bits.read(&mut self.body, self.packet_length as u32);
                (flags, copy_value)
            }).collect();

            if type_bits == 0b111 && repeat_count == 0xF {
                self.reached_end = true;
            }

            let result = FormatEntry {
                type_bits,
                repeat_count,
                flags_and_value,
            };

            println!("{}", result);

            Some(result)
        }
    }
}

pub fn decode(src_slice: &[u8]) -> Vec<u8> {
    let data = EnigmaData::deserialize(src_slice);

    let mut dst = Vec::new();
    data.decompress(&mut dst);
    dst
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serial_roundtrip() {
        const EXAMPLE: &[u8] = &[
            0x07, 0x0C, 0x00, 0x00, 0x00, 0x10, 0x05, 0x3D, 0x11, 0x8F, 0xE0, 0x00,
        ];

        let data = EnigmaData::deserialize(EXAMPLE);

        let serialized = data.serialize();

        assert_eq!(serialized, EXAMPLE);
    }

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

        print!("Encoded:\n[");
        for e in encoded.iter() {
            print!("{:#X}, ", e);
        }
        println!("]");

        let result = decode(&encoded);

        assert_eq!(&result[..], DATA);
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
