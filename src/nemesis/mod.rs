//! Functions for compressing/decompressing Nemesis-formatted data

use crate::bitstream::{IBitStream, OBitStream};
use crate::io_traits::{ReadOrdered, WriteOrdered};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use multiset::HashMultiSet;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::io::Cursor;
use std::rc::Rc;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
enum Node {
    Leaf { weight: u32, value: NibbleRun },
    Branch { child0: Rc<Node>, child1: Rc<Node> },
}

impl Node {
    pub fn leaf(value: NibbleRun, weight: u32) -> Node {
        Node::Leaf { weight, value }
    }

    pub fn branch(child0: Rc<Node>, child1: Rc<Node>) -> Node {
        Node::Branch { child0, child1 }
    }

    pub fn traverse(&self, size_map: &mut HashMap<NibbleRun, usize>) {
        match self {
            Node::Branch { child0, child1 } => {
                child0.traverse(size_map);
                child1.traverse(size_map);
            }
            Node::Leaf { value, .. } => {
                *size_map.entry(*value).or_insert(0) += 1;
            }
        }
    }
}

fn decode_header<R: ReadOrdered<u8> + ?Sized>(src: &mut R) -> HashMap<(u8, u8), NibbleRun> {
    let mut codemap = HashMap::new();

    // storage for output value to decompression buffer
    let mut out_val = 0;

    // main loop. Header is terminated by the value of 0xFF
    let mut in_val = src.read_u8().unwrap();
    while in_val != 0xFF {
        // if most significant bit is set, store the last 4 bits and discard the rest
        if in_val & 0x80 != 0 {
            out_val = in_val & 0xf;
            in_val = src.read_u8().unwrap();
        }

        let run = NibbleRun {
            nibble: out_val,
            count: ((in_val & 0x70) >> 4) + 1,
        };

        let code = src.read_u8().unwrap();
        let len = in_val & 0xF;

        // Read the run's code from stream.
        codemap.insert((code, len), run);

        in_val = src.read_u8().unwrap();
    }

    codemap
}

fn write_nibbles<W: WriteOrdered<u8> + ?Sized>(
    dst: &mut W,
    out: &mut OBitStream<u8, BigEndian>,
    nibble: u8,
    count: usize,
) {
    if count % 2 != 0 {
        out.write(dst, nibble, 4);
    }

    for _ in 0..count / 2 {
        out.write(dst, nibble | (nibble << 4), 8);
    }
}

fn decode_internal<R: ReadOrdered<u8> + ?Sized, W: WriteOrdered<u8> + ?Sized>(
    src: &mut R,
    real_dst: &mut W,
    codemap: &HashMap<(u8, u8), NibbleRun>,
    rtiles: usize,
    alt_out: bool,
) {
    // This buffer is used for alternating mode decoding.
    let mut dst = Vec::new();

    // Set bit I/O streams.
    let mut bits = IBitStream::<u8, BigEndian>::new();
    let mut out = OBitStream::<u8, BigEndian>::new();
    let mut code = bits.get(src) as u8;
    let mut len = 1;

    // When to stop decoding: number of tiles * $20 bytes per tile * 8 bits per byte.
    let total_bits = rtiles << 8;

    let mut bits_written = 0;
    while bits_written < total_bits {
        if code == 0x3f && len == 6 {
            // Bit pattern %111111; inline RLE.
            // First 3 bits are repetition count, followed by the inlined nibble.
            let count = bits.read(src, 3) as usize + 1;
            let nibble = bits.read(src, 4);

            bits_written += count as usize * 4;
            write_nibbles(&mut dst, &mut out, nibble, count);

            if bits_written >= total_bits {
                break;
            }

            // Read next bit, replacing previous data.
            code = bits.get(src) as u8;
            len = 1;
        } else {
            // Find out if the data so far is a nibble code.
            if let Some(&NibbleRun { nibble, count }) = codemap.get(&(code, len)) {
                // If it is, then it is time to output the encoded nibble run.

                bits_written += count as usize * 4;
                write_nibbles(&mut dst, &mut out, nibble, count as usize);

                if bits_written >= total_bits {
                    break;
                }

                // Read next bit, replacing previous data.
                code = bits.get(src) as u8;
                len = 1;
            } else {
                // Read next bit and append to current data.
                code = (code << 1) | bits.get(src) as u8;
                len += 1;
            }
        }
    }

    // Write out any remaining bits, padding with zeroes.
    out.flush(&mut dst, false);

    if alt_out {
        // For alternating decoding, we must now incrementally XOR and output
        // the lines.
        let mut dst = Cursor::new(&dst);
        let mut in_val: u32 = dst.read_u32::<LittleEndian>().unwrap();
        real_dst.write_u32::<LittleEndian>(in_val).unwrap();
        while dst.position() < (rtiles as u64) << 5 {
            in_val ^= dst.read_u32::<LittleEndian>().unwrap();
            real_dst.write_u32::<LittleEndian>(in_val).unwrap();
        }
    } else {
        real_dst.write_all(&dst[..rtiles << 5]).unwrap();
    }
}

/// Decompresses data that has been Nemesis encoded
///
/// If `moduled` is true then the data will be interpreted
/// as being in the Kosinski Moduled format, as used in
/// Sonic 3 and Knuckles
pub fn decode<R: ReadOrdered<u8> + ?Sized, W: WriteOrdered<u8> + ?Sized>(src: &mut R, dst: &mut W) {
    let mut rtiles = src.read_u16::<BigEndian>().unwrap() as usize;
    // sets the output mode based on the value of the first bit
    let alt_out = (rtiles & 0x8000) != 0;
    rtiles &= 0x7fff;

    if rtiles > 0 {
        let codemap = decode_header(src);
        decode_internal(src, dst, &codemap, rtiles, alt_out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct NibbleRun {
    pub nibble: u8,
    pub count: u8,
}

fn huffman_code_table(size_only_map: &HashMultiSet<usize>) -> Vec<(usize, u8)> {
    // We now build the canonical Huffman code table.
    // "base" is the code for the first nibble run with a given bit length.
    // "carry" is how many nibble runs were demoted to a higher bit length
    // at an earlier step.
    // "cnt" is how many nibble runs have a given bit length.
    let mut base = 0;
    let mut carry = 0;
    let mut cnt;
    // This vector contains the codes sorted by size.
    let mut codes = Vec::<(usize, u8)>::new();
    for i in 1_u8..=8_u8 {
        // How many nibble runs have the desired bit length.
        cnt = size_only_map.count_of(&(i as usize)) + carry;
        carry = 0;
        let mut j = 0;
        while j < cnt {
            // Sequential binary numbers for codes.
            let code = base + j;
            let mask = (1 << i) - 1;
            // We do not want any codes composed solely of 1's or which
            // start with 111111, as that sequence is reserved.
            if (i <= 6 && code == mask) || (i > 6 && code == (mask & !((1 << (i - 6)) - 1))) {
                // We must demote this many nibble runs to a longer code.
                carry = cnt - j;
                cnt = j;
                break;
            } else {
                codes.push((code, i));
            }

            j += 1;
        }
        // This is the beginning bit pattern for the next bit length.
        base = (base + cnt) << 1;
    }

    codes
}

fn encode_build_runs(src: &[u8]) -> (Vec<NibbleRun>, HashMap<NibbleRun, usize>) {
    // Unpack source so we don't have to deal with nibble IO after.
    let mut unpack = Vec::new();
    for s in src {
        unpack.push((s & 0xf0) >> 4);
        unpack.push(s & 0x0f);
    }
    unpack.push(0xff);

    // Build RLE nibble runs, RLE-encoding the nibble runs as we go along.
    // Maximum run length is 8, meaning 7 repetitions.
    let mut rle_src = Vec::<NibbleRun>::new();
    let mut counts = HashMap::<NibbleRun, usize>::new();

    let mut curr = NibbleRun {
        nibble: unpack[0],
        count: 0,
    };
    for nibble in unpack[1..].iter().copied() {
        let next = NibbleRun { nibble, count: 0 };
        if next.nibble != curr.nibble || curr.count >= 7 {
            rle_src.push(curr);
            *counts.entry(curr).or_insert(0) += 1;
            curr = next;
        } else {
            curr.count += 1;
        }
    }

    (rle_src, counts)
}

fn encode_internal<W: WriteOrdered<u8> + ?Sized>(src: &[u8], dst: &mut W, mode: bool) {
    // Build RLE nibble runs, RLE-encoding the nibble runs as we go along.
    // Maximum run length is 8, meaning 7 repetitions.
    let (rle_src, counts) = encode_build_runs(src);

    // We will use the Package-merge algorithm to build the optimal length-limited
    // Huffman code for the current file. To do this, we must map the current
    // problem onto the Coin Collector's problem.
    // Build the basic coin collection.
    let mut qt = counts
        .iter()
        // No point in including anything with weight less than 2, as they
        // would actually increase compressed file size if used.
        .filter(|(_run, &freq)| freq > 1)
        .map(|(&run, &freq)| Reverse(Rc::new(Node::leaf(run, freq as u32))))
        .collect::<BinaryHeap<Reverse<Rc<Node>>>>();

    // The base coin collection for the length-limited Huffman coding has
    // one coin list per character in length of the limmitation. Each coin list
    // has a constant "face value", and each coin in a list has its own
    // "numismatic value". The "face value" is unimportant in the way the code
    // is structured below; the "numismatic value" of each coin is the number
    // of times the underlying nibble run appears in the source file.

    // This will hold the Huffman code map.
    let mut codemap = HashMap::<NibbleRun, (usize, u8)>::new();
    // Size estimate. This is used to build the optimal compressed file.
    let mut size_est = std::usize::MAX;

    // We will solve the Coin Collector's problem several times, each time
    // ignoring more of the least frequent nibble runs. This allows us to find
    // *the* lowest file size.
    while qt.len() > 1 {
        // Make a copy of the basic coin collection.
        let q0 = qt.clone();
        // Ignore the lowest weighted item. Will only affect the next iteration
        // of the loop. If it can be proven that there is a single global
        // minimum (and no local minima for file size), then this could be
        // simplified to a binary search.
        qt.pop();

        // We now solve the Coin collector's problem using the Package-merge
        // algorithm. The solution goes here.
        let mut solution = Vec::<Rc<Node>>::new();
        // This holds the packages from the last iteration.
        let mut q = q0.clone();

        let mut target = (q0.len() - 1) << 8;
        let mut idx = 0;
        while target != 0 {
            // Gets lowest bit set in its proper place:
            let val = ((target as isize) & -(target as isize)) as usize;

            let r = 1 << idx;
            // Is the current denomination equal to the least denomination?
            if r == val {
                // If yes, take the least valuable node and put it into the solution.
                solution.push(q.pop().unwrap().0);
                target -= r;
            }

            // The coin collection has coins of values 1 to 8; copy from the
            // original in those cases for the next step.
            let mut q1 = if idx < 7 {
                q0.clone()
            } else {
                BinaryHeap::new()
            };

            // Split the current list into pairs and insert the packages into
            // the next list.
            while q.len() > 1 {
                let child1 = q.pop().unwrap().0;
                let child0 = q.pop().unwrap().0;
                q1.push(Reverse(Rc::new(Node::branch(child0, child1))));
            }
            idx += 1;
            q = q1;
        }

        // The Coin Collector's problem has been solved. Now it is time to
        // map the solution back into the length-limited Huffman coding problem.

        // To do that, we iterate through the solution and count how many times
        // each nibble run has been used (remember that the coin collection had
        // multiple coins associated with each nibble run) -- this number is the
        // optimal bit length for the nibble run for the current coin collection.
        let mut base_size_map = HashMap::<NibbleRun, usize>::new();
        for it in solution.iter() {
            it.traverse(&mut base_size_map)
        }
        let base_size_map = base_size_map;

        // With the length-limited Huffman coding problem solved, it is now time
        // to build the code table. As input, we have a map associating a nibble
        // run to its optimal encoded bit length. We will build the codes using
        // the canonical Huffman code.

        // To do that, we must invert the size map so we can sort it by code size.
        let mut size_only_map = HashMultiSet::<usize>::new();
        // This map contains lots more information, and is used to associate
        // the nibble run with its optimal code. It is sorted by code size,
        // then by frequency of the nibble run, then by the nibble run.
        let mut size_map = HashMultiSet::<(usize, usize, NibbleRun)>::new();
        for (&count_idx, &size) in base_size_map.iter() {
            let count = *counts.get(&count_idx).unwrap();
            if (6 + 7) * count < 16 + size * count {
                continue;
            }
            size_only_map.insert(size);
            size_map.insert((size, count, count_idx));
        }

        let codes = huffman_code_table(&size_only_map);

        // With the canonical table build, the codemap can finally be built.
        let temp_code_map = size_map
            .iter()
            .zip(0..codes.len())
            .map(|(it, pos)| (it.2, codes[pos]))
            .collect::<HashMap<NibbleRun, (usize, u8)>>();

        // We now compute the final file size for this code table.
        // 2 bytes at the start of the file, plus 1 byte at the end of the
        // code table.
        let tempsize_est = estimate_file_size(temp_code_map.clone(), &counts);

        // Is this iteration better than the best?
        if tempsize_est < size_est {
            // If yes, save the codemap and file size.
            codemap = temp_code_map;
            size_est = tempsize_est;
        }
    }
    // Special case.
    if qt.len() == 1 {
        let mut temp_code_map = HashMap::<NibbleRun, (usize, u8)>::new();
        let child = qt.peek().unwrap();
        let value = if let Node::Leaf { value, .. } = &*child.0 {
            *value
        } else {
            unreachable!()
        };
        temp_code_map.insert(value, (0_usize, 1_u8));
        let tempsize_est = estimate_file_size(temp_code_map.clone(), &counts);

        // Is this iteration better than the best?
        if tempsize_est < size_est {
            // If yes, save the codemap and file size.
            codemap = temp_code_map;
        }
    }
    // This is no longer needed.
    std::mem::drop(counts);

    encode_write_out(dst, mode, &rle_src, &codemap, src.len());
}

fn encode_write_out<W: WriteOrdered<u8> + ?Sized>(
    dst: &mut W,
    mode: bool,
    rle_src: &[NibbleRun],
    codemap: &HashMap<NibbleRun, (usize, u8)>,
    src_len: usize,
) {
    // We now have a prefix-free code map associating the RLE-encoded nibble
    // runs with their code. Now we write the file.

    /* --- Write Header --- */
    dst.write_u16::<BigEndian>(((mode as u16) << 15) | (src_len >> 5) as u16)
        .unwrap();
    let mut last_nibble = 0xff;
    for (run, &(code, len)) in codemap.iter() {
        // len with bit 7 set is a special device for further reducing file size, and
        // should NOT be on the table.
        if len & 0x80 != 0 {
            continue;
        }

        if run.nibble != last_nibble {
            // 0x80 marks byte as setting a new nibble.
            dst.write_u8(0x80 | run.nibble).unwrap();
            last_nibble = run.nibble;
        }

        dst.write_u8((run.count << 4) | len).unwrap();
        dst.write_u8(code as u8).unwrap();
    }

    // Mark end of header.
    dst.write_u8(0xFF).unwrap();
    /* --- End Header --- */

    // Time to write the encoded bitstream.
    let mut bits = OBitStream::<u8, BigEndian>::new();

    // The RLE-encoded source makes for a far faster encode as we simply
    // use the nibble runs as an index into the map, meaning a quick binary
    // search gives us the code to use (if in the map) or tells us that we
    // need to use inline RLE.
    for run in rle_src.iter() {
        if let Some((code, mut len)) = codemap.get(run) {
            // len with bit 7 set is a device to bypass the code table at the
            // start of the file. We need to clear the bit here before writing
            // the code to the file.
            len &= 0x7f;
            // We can have codes in the 9-12 range due to the break up of large
            // inlined runs into smaller non-inlined runs. Deal with those high
            // bits first, if needed.
            if len > 8 {
                bits.write(dst, (code >> 8) as u8, len as u32 - 8);
                len = 8;
            }
            bits.write(dst, *code as u8, len as u32);
        } else {
            bits.write(dst, 0x3f, 6);
            bits.write(dst, run.count, 3);
            bits.write(dst, run.nibble, 4);
        }
    }

    // Fill remainder of last byte with zeroes and write if needed.
    bits.flush(dst, false);
}

#[allow(dead_code)]
fn split_at_header(src: &[u8]) -> (&[u8], &[u8]) {
    let idx = src.iter().enumerate().find(|(_, s)| **s == 0xFF).unwrap().0;
    (&src[..=idx], &src[idx + 1..])
}

/// Encodes raw data into the Nemesis format
pub fn encode(src: &[u8]) -> Result<Vec<u8>, ()> {
    let mut src = src.to_vec();

    // Is the source length a multiple of 32 bits?
    // If not, pad it with zeroes until it is.
    while src.len() & 0x1f != 0 {
        src.push(0);
    }

    // Now we will build the alternating bit stream for mode 1 compression.
    let mut sin = src.clone();
    let mut i = sin.len() - 4;
    #[allow(clippy::identity_op)]
    while i > 0 {
        sin[i + 0] ^= sin[i - 4];
        sin[i + 1] ^= sin[i - 3];
        sin[i + 2] ^= sin[i - 2];
        sin[i + 3] ^= sin[i - 1];

        i -= 4;
    }

    // We will use these as output buffers, as well as an input/output
    // buffers for the padded Nemesis input.
    let mut mode_0_buf = Vec::<u8>::new();
    let mut mode_1_buf = Vec::<u8>::new();

    // Encode in both modes.
    encode_internal(&src, &mut mode_0_buf, false);
    encode_internal(&sin, &mut mode_1_buf, true);

    let mut smaller = if mode_0_buf.len() <= mode_1_buf.len() {
        mode_0_buf
    } else {
        mode_1_buf
    };

    // Pad to even size.
    if smaller.len() % 2 != 0 {
        smaller.push(0);
    }

    Ok(smaller)
}

fn estimate_file_size(
    mut codemap: HashMap<NibbleRun, (usize, u8)>,
    counts: &HashMap<NibbleRun, usize>,
) -> usize {
    // We now compute the final file size for this code table.
    // 2 bytes at the start of the file, plus 1 byte at the end of the
    // code table.
    let mut size_est = 3 * 8;
    let mut last = 0xff;
    // Start with any nibble runs with their own code.
    for (run, rhs) in codemap.iter() {
        // Each new nibble needs an extra byte.
        if last != run.nibble {
            size_est += 8;
            // Be sure to SET the last nibble to the current nibble... this
            // fixes a bug that caused file sizes to increase in some cases.
            last = run.nibble;
        }
        // 2 bytes per nibble run in the table.
        size_est += 2 * 8;
        // How many bits this nibble run uses in the file.
        size_est += *counts.get(run).unwrap() as usize * rhs.1 as usize;
    }

    // Supplementary code map for the nibble runs that can be broken up into
    // shorter nibble runs with a smaller bit length than inlining.
    let mut sup_code_map = HashMap::<NibbleRun, (usize, u8)>::new();
    // Now we will compute the size requirements for inline nibble runs.
    for (run, run_count) in counts.iter() {
        // Find out if this nibble run has a code for it.
        if !codemap.contains_key(run) {
            // Nibble run does not have its own code. We need to find out if
            // we can break it up into smaller nibble runs with total code
            // size less than 13 bits or if we need to inline it (13 bits).
            if run.count == 0 {
                // If this is a nibble run with zero repeats, we can't break
                // it up into smaller runs, so we inline it.
                size_est += (6 + 7) * run_count;
            } else if run.count == 1 {
                // We stand a chance of breaking the nibble run.

                // This case is rather trivial, so we hard-code it.
                // We can break this up only as 2 consecutive runs of a nibble
                // run with count == 0.
                let trg = NibbleRun {
                    nibble: run.nibble,
                    count: 0,
                };
                match codemap.get(&trg).copied() {
                    Some((mut code, mut len)) if len <= 6 => {
                        // The smaller nibble run has a small enough code that it is
                        // more efficient to use it twice than to inline our nibble
                        // run. So we do exactly that, by adding a (temporary) entry
                        // in the supplementary codemap, which will later be merged
                        // into the main codemap.
                        code = (code << len) | code;
                        len <<= 1;
                        size_est += len as usize * *run_count;
                        sup_code_map.insert(*run, (code, 0x80 | len));
                    }
                    _ => {
                        // The smaller nibble run either does not have its own code
                        // or it results in a longer bit code when doubled up than
                        // would result from inlining the run. In either case, we
                        // inline the nibble run.
                        size_est += (6 + 7) * run_count;
                    }
                }
            } else {
                // We stand a chance of breaking it the nibble run.

                // This is a linear optimization problem subjected to 2
                // constraints. If the number of repeats of the current nibble
                // run is N, then we have N dimensions.
                // Pointer to table of linear coefficients. This table has
                // N columns for each line.

                // Here are some hard-coded tables, obtained by brute-force:
                const LINEAR_COEFFS_2: [&[usize]; 2] = [&[3, 0], &[1, 1]];
                const LINEAR_COEFFS_3: [&[usize]; 4] =
                    [&[4, 0, 0], &[2, 1, 0], &[1, 0, 1], &[0, 2, 0]];
                const LINEAR_COEFFS_4: [&[usize]; 6] = [
                    &[5, 0, 0, 0],
                    &[3, 1, 0, 0],
                    &[2, 0, 1, 0],
                    &[1, 2, 0, 0],
                    &[1, 0, 0, 1],
                    &[0, 1, 1, 0],
                ];
                const LINEAR_COEFFS_5: [&[usize]; 10] = [
                    &[6, 0, 0, 0, 0],
                    &[4, 1, 0, 0, 0],
                    &[3, 0, 1, 0, 0],
                    &[2, 2, 0, 0, 0],
                    &[2, 0, 0, 1, 0],
                    &[1, 1, 1, 0, 0],
                    &[1, 0, 0, 0, 1],
                    &[0, 3, 0, 0, 0],
                    &[0, 1, 0, 1, 0],
                    &[0, 0, 2, 0, 0],
                ];
                const LINEAR_COEFFS_6: [&[usize]; 14] = [
                    &[7, 0, 0, 0, 0, 0],
                    &[5, 1, 0, 0, 0, 0],
                    &[4, 0, 1, 0, 0, 0],
                    &[3, 2, 0, 0, 0, 0],
                    &[3, 0, 0, 1, 0, 0],
                    &[2, 1, 1, 0, 0, 0],
                    &[2, 0, 0, 0, 1, 0],
                    &[1, 3, 0, 0, 0, 0],
                    &[1, 1, 0, 1, 0, 0],
                    &[1, 0, 2, 0, 0, 0],
                    &[1, 0, 0, 0, 0, 1],
                    &[0, 2, 1, 0, 0, 0],
                    &[0, 1, 0, 0, 1, 0],
                    &[0, 0, 1, 1, 0, 0],
                ];
                const LINEAR_COEFFS_7: [&[usize]; 21] = [
                    &[8, 0, 0, 0, 0, 0, 0],
                    &[6, 1, 0, 0, 0, 0, 0],
                    &[5, 0, 1, 0, 0, 0, 0],
                    &[4, 2, 0, 0, 0, 0, 0],
                    &[4, 0, 0, 1, 0, 0, 0],
                    &[3, 1, 1, 0, 0, 0, 0],
                    &[3, 0, 0, 0, 1, 0, 0],
                    &[2, 3, 0, 0, 0, 0, 0],
                    &[2, 1, 0, 1, 0, 0, 0],
                    &[2, 0, 2, 0, 0, 0, 0],
                    &[2, 0, 0, 0, 0, 1, 0],
                    &[1, 2, 1, 0, 0, 0, 0],
                    &[1, 1, 0, 0, 1, 0, 0],
                    &[1, 0, 1, 1, 0, 0, 0],
                    &[1, 0, 0, 0, 0, 0, 1],
                    &[0, 4, 0, 0, 0, 0, 0],
                    &[0, 2, 0, 1, 0, 0, 0],
                    &[0, 1, 2, 0, 0, 0, 0],
                    &[0, 1, 0, 0, 0, 1, 0],
                    &[0, 0, 1, 0, 1, 0, 0],
                    &[0, 0, 0, 2, 0, 0, 0],
                ];

                let n = run.count;
                // Get correct coefficient table:
                let (linear_coeffs, rows) = match n {
                    2 => (&LINEAR_COEFFS_2[..], 2),
                    3 => (&LINEAR_COEFFS_3[..], 4),
                    4 => (&LINEAR_COEFFS_4[..], 6),
                    5 => (&LINEAR_COEFFS_5[..], 10),
                    6 => (&LINEAR_COEFFS_6[..], 14),
                    7 => (&LINEAR_COEFFS_7[..], 21),
                    _ => unreachable!(),
                };

                let nibble = run.nibble;
                // Vector containing the code length of each nibble run, or 13
                // if the nibble run is not in the codemap.
                let mut run_len = Vec::<usize>::new();
                // Init vector.
                for i in 0..n {
                    // Is this run in the codemap?
                    let trg = NibbleRun { nibble, count: i };
                    let it3 = codemap.get(&trg);
                    if let Some(it3) = it3 {
                        // It is.
                        // Put code length in the vector.
                        run_len.push(it3.1 as usize);
                    } else {
                        // It is not.
                        // Put inline length in the vector.
                        run_len.push(6 + 7);
                    }
                }

                // Now go through the linear coefficient table and tally up
                // the total code size, looking for the best case.
                // The best size is initialized to be the inlined case.
                let mut best_size: usize = 6 + 7;
                let mut best_line: Option<usize> = None;
                for i in 0..rows {
                    let base = i * n as usize;

                    // Tally up the code length for this coefficient line.
                    let mut len = 0;
                    for j in 0..n as usize {
                        let c = linear_coeffs[(base + j) / linear_coeffs[0].len()]
                            [(base + j) % linear_coeffs[0].len()];
                        if c == 0 {
                            continue;
                        }

                        len += c * run_len[j];
                    }
                    // Is the length better than the best yet?
                    if len < best_size {
                        // If yes, store it as the best.
                        best_size = len;
                        best_line = Some(base);
                    }
                }
                // Have we found a better code than inlining?
                if let Some(best_line) = best_line {
                    // We have; use it. To do so, we have to build the code
                    // and add it to the supplementary code table.
                    let mut code = 0;
                    let mut len: usize = 0;
                    for i in 0..n as usize {
                        let c = linear_coeffs[(best_line + i) / linear_coeffs[0].len()]
                            [(best_line + i) % linear_coeffs[0].len()];

                        if c == 0 {
                            continue;
                        }

                        // Is this run in the codemap?
                        let trg = NibbleRun {
                            nibble,
                            count: i as u8,
                        };
                        let it3 = codemap.get(&trg);
                        if let Some(it3) = it3 {
                            // It is; it MUST be, as the other case is impossible
                            // by construction.
                            for _ in 0..c {
                                len += it3.1 as usize;
                                code <<= it3.1;
                                code |= it3.0;
                            }
                        }
                    }

                    if len != best_size {
                        // ERROR! DANGER! THIS IS IMPOSSIBLE!
                        // But just in case...
                        //tempsize_est += (6 + 7) * it->second;
                        // Just kidding, let's panic
                        panic!("ERROR! DANGER! THIS IS IMPOSSIBLE!");
                    } else {
                        // By construction, best_size is at most 12.
                        let c = best_size;
                        // Add it to supplementary code map.
                        sup_code_map.insert(*run, (code, 0x80 | c as u8));
                        size_est += best_size as usize * *run_count;
                    }
                } else {
                    // No, we will have to inline it.
                    size_est += (6 + 7) * run_count;
                }
            }
        }
    }

    codemap.extend(sup_code_map);

    // Round up to a full byte.
    if size_est & 7 != 0 {
        size_est = (size_est & !7) + 8;
    }

    size_est
}

#[cfg(test)]
mod test {
    use super::*;

    const RING_DECOMPRESSED: [u8; 448] = [
        0x00, 0x00, 0x0D, 0xC6, 0x00, 0x0D, 0xCC, 0xCC, 0x00, 0xDC, 0xCD, 0xEE, 0x0E, 0xDC, 0xDE,
        0x00, 0x0E, 0xCD, 0x00, 0x00, 0xED, 0xCE, 0x00, 0x00, 0xEC, 0xC0, 0x00, 0x00, 0xEC, 0x60,
        0x00, 0x00, 0xEC, 0x60, 0x00, 0x00, 0xEC, 0x60, 0x00, 0x00, 0xED, 0x6C, 0x00, 0x00, 0x0E,
        0xC6, 0x00, 0x00, 0x0E, 0xDC, 0x6C, 0x00, 0x00, 0xED, 0xC6, 0x66, 0x00, 0x0E, 0xED, 0xCC,
        0x00, 0x00, 0x0E, 0xEE, 0x66, 0x60, 0x00, 0x00, 0xCC, 0xC6, 0x60, 0x00, 0xEE, 0xDC, 0x66,
        0x00, 0x00, 0xEE, 0xD6, 0x60, 0x00, 0x00, 0xEC, 0x60, 0x00, 0x00, 0xED, 0xC6, 0x00, 0x00,
        0x0E, 0xC6, 0x00, 0x00, 0x0E, 0xC6, 0x00, 0x00, 0x0E, 0xC6, 0x00, 0x00, 0x0E, 0xCC, 0x00,
        0x00, 0xED, 0xCD, 0x00, 0x00, 0xDC, 0xC0, 0x00, 0xED, 0xCC, 0xD0, 0x6C, 0xCC, 0xDD, 0x00,
        0xCC, 0xDE, 0xE0, 0x00, 0xEE, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDD, 0x00, 0x00, 0x0D,
        0xCC, 0x00, 0x00, 0xDC, 0xDE, 0x00, 0x0D, 0xCD, 0xE0, 0x00, 0x0D, 0xCE, 0x00, 0x00, 0xEC,
        0xDE, 0x00, 0x00, 0xEC, 0xD0, 0x00, 0x00, 0xEC, 0xD0, 0x00, 0x00, 0xEC, 0xD0, 0x00, 0x00,
        0xEC, 0xD0, 0x00, 0x00, 0xEC, 0xDE, 0x00, 0x00, 0x0E, 0xCD, 0x00, 0x00, 0x0E, 0xCD, 0xD0,
        0x00, 0x00, 0xEC, 0xCD, 0x00, 0x00, 0x0E, 0xDC, 0x00, 0x00, 0x00, 0xEE, 0xCC, 0x00, 0x00,
        0x00, 0xCC, 0x6C, 0x00, 0x00, 0xED, 0xC6, 0xC0, 0x00, 0x0E, 0xDC, 0x60, 0x00, 0x00, 0xDC,
        0x6C, 0x00, 0x00, 0xED, 0x6C, 0x00, 0x00, 0xED, 0xC6, 0x00, 0x00, 0xED, 0xC6, 0x00, 0x00,
        0xED, 0xC6, 0x00, 0x00, 0xED, 0xC6, 0x00, 0x00, 0xED, 0x6D, 0x00, 0x00, 0xDC, 0xCE, 0x00,
        0x0E, 0xDC, 0xD0, 0x00, 0xDD, 0xCC, 0xE0, 0x00, 0xCC, 0xEE, 0x00, 0x00, 0xEE, 0x00, 0x00,
        0x00, 0x00, 0x0C, 0xC0, 0x00, 0x00, 0xC6, 0x6C, 0x00, 0x0D, 0x66, 0x66, 0xD0, 0x0D, 0x66,
        0x66, 0xD0, 0x0D, 0x66, 0x66, 0xD0, 0x0D, 0x66, 0x66, 0xD0, 0x0D, 0xC6, 0x6C, 0xD0, 0x0D,
        0xC6, 0x6C, 0xD0, 0x0E, 0xCC, 0xCC, 0xE0, 0x0E, 0xCC, 0xCC, 0xE0, 0x0E, 0xDC, 0xCD, 0xE0,
        0x0E, 0xDC, 0xCD, 0xE0, 0x0E, 0xDD, 0xDD, 0xE0, 0x0E, 0xDD, 0xDD, 0xE0, 0x00, 0xED, 0xDE,
        0x00, 0x00, 0x0E, 0xE0, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x0E, 0x6E, 0x00, 0x00, 0xED, 0x6D, 0xE0, 0xED, 0xC6, 0x66, 0xCD, 0x00,
        0xED, 0x6D, 0xE0, 0x00, 0x0E, 0x6E, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0xD0, 0x00,
        0x00, 0x00, 0xE0, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0xDC, 0xD0, 0x00, 0x00, 0x0D, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00,
        0xD0, 0x00, 0x00, 0x0E, 0xCE, 0x00, 0x0E, 0xDC, 0x6C, 0xDE, 0x00, 0x0E, 0xCE, 0x00, 0xE0,
        0x00, 0xD0, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00,
        0x00, 0x0D, 0x00, 0x00, 0x00, 0xEC, 0xE0, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x0E, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn ring_decode() {
        const DATA: &[u8; 244] =
            include_bytes!("/home/salix/Documents/Rust/megarust/roms/s1disasm/artnem/Rings.bin");

        let mut decoded = Vec::new();
        decode(&mut &DATA[..], &mut decoded);
        assert_eq!(decoded, &RING_DECOMPRESSED[..]);
    }

    #[test]
    fn ring_roundtrip() {
        roundtrip(&RING_DECOMPRESSED)
    }

    fn roundtrip(data: &[u8]) {
        let compressed = encode(data).unwrap();
        println!("Attempting to decode:\n{:X?}", split_at_header(&compressed));
        let mut result = Vec::new();
        decode(&mut &compressed[..], &mut result);

        if result != data {
            eprintln!("Expected length: {:#X}", data.len());
            eprintln!("Actual length: {:#X}", result.len());

            eprintln!("Expected:\n{:X?}\nActual:\n{:X?}", data, result);

            for (idx, (ex, ac)) in data.iter().zip(result.iter()).enumerate() {
                if ex != ac {
                    eprintln!("[{:#05X}] {:#04X} != {:#04X}", idx, ex, ac);
                }
            }

            panic!();
        }
    }

    #[test]
    fn roundtrip_string() {
        const DATA: &[u8; 0x60] = b"Lorem ipsum dolor sit amet\0heeeeeeeeeeeeeeeeck why is this so hardpaddingpaddingpaddingpaddingpa";
        roundtrip(&DATA[..]);
    }
}
