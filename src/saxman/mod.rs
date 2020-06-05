use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use std::io::{Cursor, Write};
use std::collections::LinkedList;
use byteorder::LittleEndian;
use crate::bitstream::OBitStream;
use crate::io_traits::WriteOrdered;

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
            let source = ((base.wrapping_sub(dst.position() as u16)) & 0xFFF)
                .wrapping_add(dst.position() as u16)
                .wrapping_sub(0x1000);

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

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
enum EdgeType {
    Invalid,
    Symbolwise,
    Dictionary,
    ZeroFill,
}

// Computes the type of edge that covers all of the "len" vertices
// starting from "off" vertices ago. Returns EdgeType::invalid if there
// is no such edge.
fn match_type(_dist: usize, len: usize) -> EdgeType {
    // Preconditions:
    // len >= 1 && len <= LookAheadBufSize && dist != 0 && dist <= SearchBufSize
    /*assert!(len >= 1);
    assert!(len <= LOOKAHEAD_BUF_SIZE);
    assert_ne!(dist, 0);
    assert!(dist <= SEARCH_BUF_SIZE);*/

    if len == 1 {
        EdgeType::Symbolwise
    } else if len == 2 {
        EdgeType::Invalid
    } else {
        EdgeType::Dictionary
    }
}

const FIRST_MATCH_POSITION: usize = 0;
const NUM_TERM_BITS: usize = 0;
const NUM_DESC_BITS: usize = 8;
const NEED_EARLY_DESCRIPTOR: bool = false;
const LOOKAHEAD_BUF_SIZE: usize = 18;
const SEARCH_BUF_SIZE: usize = 4096;

/*
 * Graph structure for optimal LZSS encoding. This graph is a directed acyclic
 * graph (DAG) by construction, and is automatically sorted topologically.
 * The template parameter is an adaptor class/structure with the following
 * members:
 *  struct LZSSAdaptor {
 *  	using stream_t     = uint8_t;
 *  	using stream_endian_t = BigEndian;
 *  	using descriptor_t = uint16_t;
 *  	using descriptor_endian_t = LittleEndian;
 *  	enum class EdgeType : size_t {
 *  		invalid,
 *  		// other cases
 *  	};
 *  	constexpr static size_t const NumDescBits = sizeof(descriptor_t) * 8;
 *  	// Number of bits used in descriptor bitfield to signal the end-of-file
 *  	// marker sequence.
 *  	constexpr static size_t const NumTermBits = 2;
 *  	// Flag that tells the compressor that new descriptor fields are needed
 *  	// as soon as the last bit in the previous one is used up.
 *  	constexpr static bool const NeedEarlyDescriptor = true;
 *  	// Flag that marks the descriptor bits as being in little-endian bit
 *  	// order (that is, lowest bits come out first).
 *  	constexpr static bool const DescriptorLittleEndianBits = true;
 *  	// How many characters to skip looking for matchs for at the start.
 *  	constexpr static size_t const FirstMatchPosition = 0;
 *  	// Size of the search buffer.
 *  	constexpr static size_t const SearchBufSize = 8192;
 *  	// Size of the look-ahead buffer.
 *  	constexpr static size_t const LookAheadBufSize = 256;
 *  	// Total size of the sliding window.
 *  	constexpr static size_t const SlidingWindowSize = SearchBufSize +
 * LookAheadBufSize;
 *  	// Computes the type of edge that covers all of the "len" vertices
 * starting from
 *  	// "off" vertices ago.
 *  	// Returns EdgeType::invalid if there is no such edge.
 *  	constexpr static EdgeType match_type(size_t const dist, size_t const
 * len) noexcept
 *  	// Given an edge type, computes how many bits are used in the descriptor
 * field. constexpr static size_t desc_bits(EdgeType const type) noexcept;
 *  	// Given an edge type, computes how many bits are used in total by this
 * edge.
 *  	// A return of "numeric_limits<size_t>::max()" means "infinite",
 *  	// or "no edge".
 *  	constexpr static size_t edge_weight(EdgeType const type) noexcept;
 *  	// Function that finds extra matches in the data that are specific to
 * the
 *  	// given encoder and not general LZSS dictionary matches. May be
 * constexpr. static void extra_matches(stream_t const *data, size_t const
 * basenode, size_t const ubound, size_t const lbound,
 *  	                          LZSSGraph<KosinskiAdaptor>::MatchVector
 * &matches) noexcept;
 *  	// Function that computes padding between modules, if any. May be
 * constexpr. static size_t get_padding(size_t const totallen) noexcept;
 */
struct SaxGraph<'a> {
    /*using EdgeType        = typename Adaptor::EdgeType;
    using stream_t        = typename Adaptor::stream_t;
    using stream_endian_t = typename Adaptor::stream_endian_t;
    using Node_t          = AdjListNode<Adaptor>;
    using AdjList         = std::list<Node_t>;
    using MatchVector     = std::vector<Node_t>;
    using SlidingWindow_t = SlidingWindow<Adaptor>;*/

    // Adjacency lists for all the nodes in the graph.
    data: &'a [u8],
}

impl SaxGraph<'_> {
    // Constructor: creates the graph from the input file.
    pub fn new(data: &[u8]) -> SaxGraph {
        SaxGraph {
            data,
        }
    }

    pub fn find_optimal_parse(&self) -> LinkedList<AdjListNode> {
        let num_nodes: usize = self.data.len() - FIRST_MATCH_POSITION;
        // Auxiliary data structures:
        // * The parent of a node is the node that reaches that node with the
        //   lowest cost from the start of the file.
        let mut parents = vec![0_usize; num_nodes + 1];
        // * This is the edge used to go from the parent of a node to said node.
        let mut pedges = vec![AdjListNode::new(); num_nodes + 1];
        // * This is the total cost to reach the edge. They start as high as
        //   possible for all nodes but the first, which starts at 0.
        let mut costs = vec![std::usize::MAX; num_nodes + 1];
        costs[0] = 0;
        // * And this is a vector that tallies up the amount of bits in
        //   the descriptor bitfield for the shortest path up to this node.
        //   After tallying up the ending node, the end-of-file marker may cause
        //   an additional dummy descriptor bitfield to be emitted; this vector
        //   is used to counteract that.
        let mut desccosts = vec![std::usize::MAX; num_nodes + 1];
        desccosts[0] = 0;

        // Extracting distance relax logic from the loop so it can be used more often.
        let mut relax = |ii: usize, basedesc: usize, elem: &AdjListNode, desccosts: &mut Vec<usize>| {
            // Need destination ID and edge weight.
            let nextnode: usize = elem.get_dest() - FIRST_MATCH_POSITION;
            let mut wgt: usize = costs[ii] + elem.get_weight();
            // Compute descriptor bits from using this edge.
            let mut desccost: usize = basedesc + desc_bits(elem.get_type());
            if nextnode == self.data.len() {
                // This is the ending node. Add the descriptor bits for the
                // end-of-file marker.
                wgt += NUM_TERM_BITS;
                desccost += NUM_TERM_BITS;
                // If the descriptor bitfield had exactly 0 bits left after
                // this, we may need to emit a new descriptor bitfield (the
                // full Adaptor::NumDescBits bits). Otherwise, we need to
                // pads the last descriptor bitfield to full size. This line
                // accomplishes both.
                let descmod: usize = desccost % NUM_DESC_BITS;
                if descmod != 0 || NEED_EARLY_DESCRIPTOR {
                    wgt += NUM_DESC_BITS - descmod;
                    desccost += NUM_DESC_BITS - descmod;
                }
                // Compensate for the Adaptor's padding, if any.
                wgt += get_padding(wgt);
            }
            // Is the cost to reach the target node through this edge less
            // than the current cost?
            if costs[nextnode] > wgt {
                // If so, update the data structures with new best edge.
                costs[nextnode]     = wgt;
                parents[nextnode]   = ii;
                pedges[nextnode]    = elem.clone();
                desccosts[nextnode] = desccost;
            }
        };

        // Since the LZSS graph is a topologically-sorted DAG by construction,
        // computing the shortest distance is very quick and easy: just go
        // through the nodes in order and update the distances.
        let mut win_set = create_sliding_window(self.data);
        for ii in 0..num_nodes {
            // Get remaining unused descriptor bits up to this node.
            let basedesc: usize = desccosts[ii];
            // Start with the literal/symbolwise encoding of the current node.
            {
                let ty: EdgeType = match_type(0, 1);
                // TODO: Determine if this is correct, seems too simple
                let val = self.data[ii + FIRST_MATCH_POSITION];
                relax(ii, basedesc, &AdjListNode::with_symbol(ii + FIRST_MATCH_POSITION, val, ty), &mut desccosts);
            }
            // Get the adjacency list for this node.
            for win in win_set.iter_mut() {
                let mut matches = win.find_extra_matches();
                if matches.is_empty() {
                    matches = win.find_matches();
                }

                for elem in matches {
                    if elem.get_type() != EdgeType::Invalid {
                        relax(ii, basedesc, &elem, &mut desccosts);
                    }
                }
                win.slide_window();
            }
        }

        // This is what we will produce.
        let mut parse_list = LinkedList::<AdjListNode>::new();
        let mut ii: usize = num_nodes;
        while ii != 0 {
            // Insert the edge up front...
            parse_list.push_front(pedges[ii].clone());
            // ... and switch to parent node.
            ii = parents[ii];
        }

        // We are done: this is the optimal parsing of the input file, giving
        // *the* best possible compressed file size.
        parse_list
    }
}

struct SaxOStream<'a, W: WriteOrdered<u8>> {
    // Where we will output to.
    out: &'a mut W,

    // Internal bitstream output buffer.
    // TODO: THIS NEEDS TO BE IN LITTLE ENDIAN BIT ORDER
    bits: OBitStream<u8, LittleEndian>,

    // Internal parameter buffer.
    buffer: Vec<u8>,
}

impl<W: Write> SaxOStream<'_, W> {
    pub fn new(out: &mut W) -> SaxOStream<W> {
        SaxOStream {
            out,
            bits: OBitStream::new(),
            buffer: Vec::new(),
        }
    }

    /// Writes a bit to the descriptor bitfield. When the descriptor field is
    /// full, outputs it and the output parameter buffer.
    pub fn descbit(&mut self, bit: bool) {
        if NEED_EARLY_DESCRIPTOR {
            if self.bits.push(self.out, bit) {
                self.flushbuffer();
            }
        } else {
            if self.bits.waiting_bits() == 0 {
                self.flushbuffer();
            }

            self.bits.push(self.out, bit);
        }
    }

    /// Puts a byte in the output buffer.
    pub fn putbyte(&mut self, c: u8) {
        self.buffer.push(c);
    }

    fn flushbuffer(&mut self) {
        self.out.write_all(&self.buffer).unwrap();
        self.buffer.clear();
    }
}

impl<W: WriteOrdered<u8>> Drop for SaxOStream<'_, W> {
    // writes anything that hasn't been written.
    fn drop(&mut self) {
        // We need a dummy descriptor field if we have exactly zero bits left
        // on the previous descriptor field; this is because the decoder will
        // immediately fetch a new descriptor field when the previous one has
        // expired, and we don't want it to be the terminating sequence.
        // First, save current state.
        let needdummydesc = self.bits.waiting_bits() == 0;
        // Now, flush the queue if needed.
        self.bits.flush(self.out, false);
        if NEED_EARLY_DESCRIPTOR && needdummydesc {
            // We need to add a dummy descriptor field; so add it.
            self.out.write_all(&[0x00]).unwrap();
        }
        // Now write the terminating sequence if it wasn't written already.
        self.flushbuffer();
    }
}


#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
struct MatchInfo {
    // How many characters back does the match begin at.
    distance: usize,
    // How long the match is.
    length: usize,
}

#[derive(Clone, Copy)]
union NodeInner {
    match_info: MatchInfo,
    symbol: u8,
}

#[derive(Clone)]
struct AdjListNode {
    // The first character after the match ends.
    pub currpos: usize,

    // Cost, in bits, of "covering" all of the characters in the match.
    pub edge_type: EdgeType,

    pub inner: NodeInner,
}

// Saxman allows encoding of a sequence of zeroes with no previous
// match.
fn extra_matches(data: &[u8], basenode: usize, ubound: usize, _lbound: usize) -> Vec<AdjListNode> {
    // Can't encode zero match after this point.
    if basenode >= SEARCH_BUF_SIZE - 1 {
        return Vec::new();
    }

    // Try matching zeroes.
    let mut jj: usize = 0;
    let end: usize = ubound - basenode;
    while data[basenode + jj] == 0 {
        jj += 1;
        if jj >= end {
            break;
        }
    }

    // Need at least 3 zeroes in sequence.
    if jj >= 3 {
        // Got them, so add them to the list.
        let mut matches = Vec::new();
        for length in 3..=jj {
            matches.push(AdjListNode::with_match(basenode, MatchInfo { length, distance: std::usize::MAX }, EdgeType::ZeroFill));
        }
        matches
    } else {
        Vec::new()
    }
}

struct SlidingWindow<'a> {
    // Source file data and its size; one node per character in source file.
    data: &'a [u8],
    srchbufsize: usize,
    minmatchlen: usize,
    basenode: usize,
    ubound: usize,
    lbound: usize,
    edge_type: EdgeType,
}

impl SlidingWindow<'_> {
    pub fn new(data: &[u8], srchbufsize: usize, minmatchlen: usize, labuflen: usize, edge_type: EdgeType) -> SlidingWindow {
        SlidingWindow {
            data,
            srchbufsize,
            minmatchlen,
            basenode: FIRST_MATCH_POSITION,
            ubound: std::cmp::min(labuflen + FIRST_MATCH_POSITION /* basenode */, data.len()),
            lbound: FIRST_MATCH_POSITION /* basenode */.saturating_sub(srchbufsize),
            edge_type,
        }
    }

    pub fn search_buf_size(&self) -> usize {
        self.basenode - self.lbound   
    }

    pub fn lookahead_buf_size(&self) -> usize {
        self.ubound - self.basenode
    }

    #[allow(dead_code)]
    pub fn window_size(&self) -> usize {
        self.ubound - self.lbound
    }

    pub fn slide_window(&mut self) -> bool {
        if self.ubound != self.data.len() {
            self.ubound += 1;
        }
        if self.basenode != self.data.len() {
            self.basenode += 1;
        }
        if self.search_buf_size() > self.srchbufsize {
            self.lbound += 1;
        }

        self.lookahead_buf_size() != 0
    }

    pub fn find_matches(&self) -> Vec<AdjListNode> {
        let end: usize = self.lookahead_buf_size();

        // First node is special.
        if self.search_buf_size() == 0 {
            return Vec::new();
        }

        let mut ii: usize = self.basenode - 1;
        let mut best_pos: usize = 0;
        let mut best_len: usize = 0;

        loop {
            // Keep looking for dictionary matches.
            let mut jj: usize = 0;
            while jj < end && self.data[ii + jj] == self.data[self.basenode + jj] {
                jj += 1;
            }
            if best_len < jj {
                best_pos = ii;
                best_len = jj;
            }
            if jj == end {
                break;
            }

            let cond = ii > self.lbound;
            if !cond {
                break;
            }

            ii -= 1;
        }

        if best_len >= self.minmatchlen {
            // We have found a match that links (basenode) with
            // (basenode + best_len) with length (best_len) and distance
            // equal to (basenode-best_pos).
            // Add it, and all prefixes, to the list, as long as it is a better
            // match.

            let mut matches = Vec::new();
            for length in self.minmatchlen..=best_len {
                matches.push(AdjListNode::with_match(self.basenode, MatchInfo { distance: self.basenode - best_pos, length }, self.edge_type.clone()));
            }
            matches
        } else {
            Vec::new()
        }
    }

    fn find_extra_matches(&self) -> Vec<AdjListNode> {
        // Get extra dictionary matches dependent on specific encoder.
        extra_matches(self.data, self.basenode, self.ubound, self.lbound)
    }
}

fn desc_bits(_edge_type: EdgeType) -> usize {
    // Saxman always uses a single bit descriptor
    1
}

fn get_padding(_total_len: usize) -> usize {
    // Saxman needs no additional padding at the end of the file
    0
}

fn create_sliding_window(data: &[u8]) -> [SlidingWindow; 1] {
    [SlidingWindow::new(data, SEARCH_BUF_SIZE, 3, LOOKAHEAD_BUF_SIZE, EdgeType::Dictionary)]
}

fn edge_weight(edge_type: EdgeType) -> usize {
    match edge_type {
        EdgeType::Symbolwise => {
            // 8-bit value.
            desc_bits(edge_type) + 8
        }
        EdgeType::Dictionary |
        EdgeType::ZeroFill => {
            // 12-bit offset, 4-bit length.
            desc_bits(edge_type) + 12 + 4
        }
        EdgeType::Invalid => {
            std::usize::MAX
        }
    }
}


impl AdjListNode {
    pub fn new() -> AdjListNode {
        AdjListNode::with_symbol(0, 0, EdgeType::Invalid)
    }

    pub fn with_symbol(currpos: usize, symbol: u8, edge_type: EdgeType) -> Self {
        AdjListNode {
            currpos,
            edge_type,
            inner: NodeInner { symbol },
        }
    }

    pub fn with_match(currpos: usize, match_info: MatchInfo, edge_type: EdgeType) -> Self {
        AdjListNode {
            currpos,
            edge_type,
            inner: NodeInner { match_info }
        }
    }

    pub fn get_pos(&self) -> usize {
        self.currpos
    }

    pub fn get_dest(&self) -> usize {
        self.currpos + self.get_length()
    }

    pub fn get_weight(&self) -> usize {
        edge_weight(self.edge_type.clone())
    }

    pub fn get_distance(&self) -> usize {
        if self.edge_type == EdgeType::Symbolwise {
            0
        } else {
            unsafe { self.inner.match_info.distance }
        }
    }

    pub fn get_length(&self) -> usize {
        if self.edge_type == EdgeType::Symbolwise {
            1
        } else {
            unsafe { self.inner.match_info.length }
        }
    }

    pub fn get_symbol(&self) -> u8 {
        if self.edge_type == EdgeType::Symbolwise {
            unsafe { self.inner.symbol }
        } else {
            0xFF
        }
    }

    pub fn get_type(&self) -> EdgeType {
        self.edge_type.clone()
    }
}

pub fn encode<W: WriteOrdered<u8>>(data: &[u8], dst: &mut W) {
    // Compute optimal Saxman parsing of input file.
    let list = SaxGraph::new(data).find_optimal_parse();
    let mut out = SaxOStream::new(dst);

    // Go through each edge in the optimal path.
    for edge in list.iter() {
        match edge.get_type() {
            EdgeType::Symbolwise => {
                out.descbit(true);
                out.putbyte(edge.get_symbol());
            }
            EdgeType::Dictionary |
            EdgeType::ZeroFill => {
                let len: usize  = edge.get_length();
                let dist: usize = edge.get_distance();
                let pos: usize  = edge.get_pos();
                let base: usize = (pos - dist - 0x12) & 0xFFF;
                let lo = base as u8;
                let hi = ((len - 3) & 0x0F) as u8 | ((base >> 4) & 0xF0) as u8;
                out.descbit(false);
                out.putbyte(lo);
                out.putbyte(hi);
            }
            EdgeType::Invalid => unreachable!("Invalid edge type"),
        }
    }
}

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

    #[test]
    fn basic_roundtrip() {
        //roundtrip(&[0x00, 0x01, 0x02, 0x03, 0x04, 0xFF, 0x00, 0xFF, 0x00, 0x12, 0x34, 0xAA, 0xBB]);
        roundtrip(&[0x00, 0x01, 0x02, 0x03]);
    }

    fn roundtrip(expected: &[u8]) {
        let mut encoded = Vec::new();
        encode(expected, &mut encoded);

        print!("Encoded:\n[");
        for d in encoded.iter() {
            print!("{:#04X}, ", d);
        }
        println!("]\n");
        
        let actual = decode(&encoded, false);

        assert_eq!(actual, expected);
    }
}
