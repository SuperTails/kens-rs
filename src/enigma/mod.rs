use std::collections::{HashMap, HashSet};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use crate::bitstream::{OBitStream, IBitStream, ReadOrdered, WriteOrdered};
use std::io::Cursor;
use std::convert::TryInto;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct BaseFlagIo {
    n: u16,
}

impl BaseFlagIo {
    pub fn new(n: u16) -> BaseFlagIo {
        BaseFlagIo {
            n
        }
    }

    #[allow(clippy::identity_op)]
    pub fn read_bitfield<R: ReadOrdered<u16> + ?Sized>(self, src: &mut R, bits: &mut IBitStream::<u16, BigEndian>) -> u16 {
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
    pub fn write_bitfield<W: WriteOrdered<u16> + ?Sized>(self, dst: &mut W, bits: &mut OBitStream<u16, BigEndian>, flags: u16) {
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
fn flush_buffer<W: WriteOrdered<u16> + ?Sized>(dst: &mut W, buf: &mut Vec<u16>, bits: &mut OBitStream<u16, BigEndian>, mask: BaseFlagIo, packet_length: u16) {
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
			if pos + 1 < unpack.len() && next != incrementing_value &&
			    (delta == -1 || delta == 0 || delta == 1) {
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

/*pub fn decode<W: Write>(src: &[u8]) {
// Info Byte, Flag, Count and Offset (with initial values)
	let InfoByte: u8 = 0;
	let mut IBP: u8 = 8;
	let Count: u8 = 0;
	let Offset: u16 = 0;
//	unsigned short Size = 0;		// Size of the compressed data

// Other info
	let Byte: u8;				// Used to store a Byte temporarly
	let Pointer: i32;					// Used to store a Pointer temporarly
	let i: i32;							// Counter

//------------------------------------------------------------------------------------------------

    let mut dst = Cursor::new(Vec::new());

    loop {
		if IBP == 8 {
            IBP=0;
            if fread(&InfoByte, 1, 1, Src) == 0 { break }
            if ftell(Src) >= Location + Size { break }
        }

        let Flag = (InfoByte >> IBP) & 1 != 0;
        IBP += 1;

        if !Flag {
            Offset=0; // See 3 lines below

            if fread(&Offset, 1, 1, Src)==0 { break }
            if ftell(Src) >= Location + Size { break }
            if fread(&Count, 1, 1, Src)==0 { break }
            if ftell(Src) >= Location + Size { break }

            Offset = ( Offset | ((Count & 0xF0) << 4) ) + 0x12; // Can be improved
            Offset |= ftell(Dst) & 0xF000;
            Count&=0x0F;
            Count+=3;
            if Offset >= ftell(Dst) {
                Offset -= 0x1000;
            }
            if Offset < ftell(Dst) {
                for i in 0..Count {
                    Pointer = ftell(Dst);
                    fseek(Dst, Offset + i, SEEK_SET);
                    if (fread(&Byte, 1, 1, Dst)==0) break;
                    fseek(Dst, Pointer, SEEK_SET);
                    fwrite(&Byte, 1, 1, Dst);
                }
            } else {
                Byte=0;
                for i in 0..Count {
                    fwrite(&Byte, 1, 1, Dst);
                }
            }
            break;
        } else {
            if fread(&Byte, 1, 1, Src) == 0 { break }
            if ftell(Src) >= Location + Size { break }
            dst.write(&[Byte]);
            break;
        }
    }
}*/