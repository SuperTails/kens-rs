use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use std::io::{Write, Cursor};

pub fn decode(src: &[u8], is_z80: bool) -> Vec<u8> {
    let mut src = if is_z80 {
        let size = BigEndian::read_u16(&src[0..2]) as usize;
        Cursor::new(&src[2..size + 2])
    } else {
        Cursor::new(&src[..])
    };

    let mut dst = Cursor::new(Vec::new());
    while src.position() != src.get_ref().len() as u64 {
        decode_single_field(&mut src, &mut dst);
    }

    dst.into_inner()
}

fn decode_single_field(src: &mut Cursor<&[u8]>, dst: &mut Cursor<Vec<u8>>) {
    let mut description = [false; 8];
    let description_byte = src.read_u8().unwrap();
    for (idx, bit) in description.iter_mut().enumerate() {
        *bit = description_byte & (1 << idx) != 0;
    }

    for &bit in description.iter() {
        if src.position() == src.get_ref().len() as u64 {
            break;
        }

        if bit {
            dst.write_all(&[src.read_u8().unwrap()]).unwrap();
        } else {
            let lo = src.read_u8().unwrap();
            let hi = src.read_u8().unwrap();

            let count = (hi & 0xF) + 3;

            let base = ((hi as u16 & 0xF0) << 4) | lo as u16;
            let base = (base + 0x12) & 0xFFF;
            let source = ((base.wrapping_sub(dst.position() as u16)) & 0xFFF).wrapping_add(dst.position() as u16).wrapping_sub(0x1000);

            if source as u64 >= dst.position() {
                // Zero fill
                for _ in 0..count {
                    dst.write_all(&[0]).unwrap();
                }
            } else {
                for _ in 0..count {
                    dst.write_all(&[src.read_u8().unwrap()]).unwrap();
                }
            }
        }
    }
}

/*fn encode(src: &[u8], dst: &ostream) {
    using EdgeType   = typename SaxmanAdaptor::EdgeType;
    using SaxGraph   = LZSSGraph<SaxmanAdaptor>;
    using SaxOStream = LZSSOStream<SaxmanAdaptor>;

    // Compute optimal Saxman parsing of input file.
    SaxGraph          enc(Data, Size);
    SaxGraph::AdjList list = enc.find_optimal_parse();
    SaxOStream        out(Dst);

    // Go through each edge in the optimal path.
    for (auto const& edge : list) {
        switch (edge.get_type()) {
        case EdgeType::symbolwise:
            out.descbit(1);
            out.putbyte(edge.get_symbol());
            break;
        case EdgeType::dictionary:
        case EdgeType::zerofill: {
            size_t const len  = edge.get_length();
            size_t const dist = edge.get_distance();
            size_t const pos  = edge.get_pos();
            size_t const base = (pos - dist - 0x12U) & 0xFFFU;
            size_t const low  = base & 0xFFU;
            size_t const high =
                ((len - 3U) & 0x0FU) | ((base >> 4) & 0xF0U);
            out.descbit(0);
            out.putbyte(low);
            out.putbyte(high);
            break;
        }
        case EdgeType::invalid:
            // This should be unreachable.
            std::cerr << "Compression produced invalid edge type "
                        << static_cast<size_t>(edge.get_type()) << std::endl;
            __builtin_unreachable();
        }
    }
}*/

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn zero_fill() {
        const DATA: &[u8] = &[0x00, 0x03, 0x00, 0x00, 0xFF];

        let decoded = decode(DATA, true);

        const EXPECTED: &[u8] = &[0x00; 0x12];

        assert_eq!(decoded, EXPECTED);
    }
}