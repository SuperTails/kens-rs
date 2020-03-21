use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt};
use num_traits::PrimInt;
use std::marker::PhantomData;

pub trait ReadOrdered<T: PrimInt>: ReadBytesExt {
    fn read_ordered<Order: ByteOrder>(&mut self) -> std::io::Result<T>;
}
pub trait WriteOrdered<T: PrimInt>: WriteBytesExt {
    fn write_ordered<Order: ByteOrder>(&mut self, value: T) -> std::io::Result<()>;
}

/*impl<T: PrimInt, R: ReadOrdered<T>> ReadOrdered<T> for &'_ mut R {
    fn read_ordered<Order: ByteOrder>(&mut self) -> std::io::Result<T> {
        self.read_ordered::<Order>()
    }
}
impl<T: PrimInt, W: WriteOrdered<T>> WriteOrdered<T> for &'_ mut W {
    fn write_ordered<Order: ByteOrder>(&mut self, value: T) -> std::io::Result<()> {
        self.write_ordered::<Order>(value)
    }
}*/

macro_rules! make_impl {
    { $len:literal, $inttype:ty, $funcname:ident, $funcname2:ident } => {
        impl<T: ReadBytesExt> ReadOrdered<$inttype> for T {
            fn read_ordered<Order: ByteOrder>(&mut self) -> std::io::Result<$inttype> {
                self.$funcname::<Order>()
            }
        }
        impl<T: WriteBytesExt> WriteOrdered<$inttype> for T {
            fn write_ordered<Order: ByteOrder>(&mut self, value: $inttype) -> std::io::Result<()> {
                self.$funcname2::<Order>(value)
            }
        }
    };
}

// These two are special cased in byteorder because they don't need an ordering
impl<T: ReadBytesExt> ReadOrdered<u8> for T {
    fn read_ordered<Order: ByteOrder>(&mut self) -> std::io::Result<u8> {
        self.read_u8()
    }
}
impl<T: ReadBytesExt> ReadOrdered<i8> for T {
    fn read_ordered<Order: ByteOrder>(&mut self) -> std::io::Result<i8> {
        self.read_i8()
    }
}
impl<T: WriteBytesExt> WriteOrdered<u8> for T {
    fn write_ordered<Order: ByteOrder>(&mut self, value: u8) -> std::io::Result<()> {
        self.write_u8(value)
    }
}
impl<T: WriteBytesExt> WriteOrdered<i8> for T {
    fn write_ordered<Order: ByteOrder>(&mut self, value: i8) -> std::io::Result<()> {
        self.write_i8(value)
    }
}

make_impl! { 2, u16, read_u16, write_u16 }
make_impl! { 2, i16, read_i16, write_i16 }
make_impl! { 4, u32, read_u32, write_u32 }
make_impl! { 4, i32, read_i32, write_i32 }
make_impl! { 8, u64, read_u64, write_u64 }
make_impl! { 8, i64, read_i64, write_i64 }

pub struct IBitStream<T: PrimInt, Order: ByteOrder> {
    read_bits: u32,
    byte_buffer: T,
    _order: PhantomData<Order>,
}

impl<T: PrimInt, Order: ByteOrder> IBitStream<T, Order> {
    fn bit_width() -> u32 {
        T::zero().count_zeros()
    }

    fn check_buffer<R: ReadOrdered<T> + ?Sized>(&mut self, src: &mut R) {
        if self.read_bits != 0 {
            return;
        }

        match src.read_ordered::<Order>() {
            Ok(read) => {
                self.byte_buffer = read;
                self.read_bits = Self::bit_width();
            }
            Err(err) => {
                todo!(
                    "This doesn't make sense: self.read_bits = 16; but the error was {}",
                    err
                );
            }
        }
    }

    pub fn new<R: ReadOrdered<T> + ?Sized>(src: &mut R) -> Self {
        let mut result = Self {
            read_bits: Self::bit_width(),
            byte_buffer: T::zero(),
            _order: PhantomData,
        };
        result.byte_buffer = src.read_ordered::<Order>().unwrap();
        result
    }

    /// Gets a single bit from the stream. Remembers previously read bits,
    /// and gets a character from the actual stream once all bits in the current
    /// byte have been read.
    pub fn get<R: ReadOrdered<T> + ?Sized>(&mut self, src: &mut R) -> bool {
        self.check_buffer(src);
        self.read_bits -= 1;
        let bit = (self.byte_buffer >> self.read_bits as usize) & T::one();
        self.byte_buffer = self.byte_buffer ^ (bit << self.read_bits as usize);
        bit != T::zero()
    }

    /// Gets a single bit from the stream. Remembers previously read bits,
    /// and gets a character from the actual stream once all bits in the current
    /// byte have been read.
    /// Treats bits as being in the reverse order of the get function.
    pub fn pop<R: ReadOrdered<T>>(&mut self, src: &mut R) -> bool {
        self.read_bits -= 1;
        let bit = self.byte_buffer & T::one();
        self.byte_buffer = self.byte_buffer >> 1;
        self.check_buffer(src);
        bit != T::zero()
    }

    /// Reads up to sizeof(T) * 8 bits from the stream. Remembers previously read bits,
    /// and gets a character from the actual stream once all bits in the current
    /// byte have been read.
    pub fn read<R: ReadOrdered<T> + ?Sized>(&mut self, src: &mut R, cnt: u32) -> T {
        self.check_buffer(src);
        if self.read_bits < cnt {
            let delta = cnt - self.read_bits;
            let bits = self.byte_buffer << delta as usize;
            self.byte_buffer = src.read_ordered::<Order>().unwrap();
            self.read_bits = Self::bit_width() - delta;
            let newbits = self.byte_buffer >> self.read_bits as usize;
            self.byte_buffer = self.byte_buffer ^ (newbits << self.read_bits as usize);
            bits | newbits
        } else {
            self.read_bits -= cnt;
            let bits = self.byte_buffer >> self.read_bits as usize;
            self.byte_buffer = self.byte_buffer ^ (bits << self.read_bits as usize);
            bits
        }
    }
}

pub struct OBitStream<T: PrimInt, Order: ByteOrder> {
    waiting_bits: u32,
    byte_buffer: T,
    _order: PhantomData<Order>,
}

impl<T: PrimInt, Order: ByteOrder> OBitStream<T, Order> {
    pub fn bit_width() -> u32 {
        T::zero().count_zeros()
    }

    pub fn new() -> Self {
        OBitStream {
            waiting_bits: 0,
            byte_buffer: T::zero(),
            _order: PhantomData,
        }
    }

    /// Puts a single bit into the stream. Remembers previously written bits,
    /// and outputs a character to the actual stream once there
    /// are `bit_width()` bits stored in the buffer.
    ///
    /// This puts the new bit as the LSB, i.e. on the right side of `byte_buffer`
    pub fn put<W: WriteOrdered<T>>(&mut self, mut dst: W, data: bool) -> bool {
        let bit = if data { T::one() } else { T::zero() };

        self.byte_buffer = (self.byte_buffer << 1) | bit;
        self.waiting_bits += 1;
        if self.waiting_bits >= Self::bit_width() {
            // Buffer is full
            dst.write_ordered::<Order>(self.byte_buffer).unwrap();
            self.waiting_bits = 0;
            true
        } else {
            false
        }
    }

    /// Puts a single bit into the stream. Remembers previously written bits,
    /// and outputs a character to the actual stream once there are at least
    /// `bit_width()` bits stored in the buffer.
    ///
    /// Treats bits as being in the reverse order of the put function, i.e.
    /// it stores new bits on top of/on the left of `byte_buffer`
    pub fn push<W: WriteOrdered<T>>(&mut self, dst: &mut W, data: bool) -> bool {
        let bit = if data { T::one() } else { T::zero() };

        self.byte_buffer = self.byte_buffer | (bit << self.waiting_bits as usize);
        self.waiting_bits += 1;
        if self.waiting_bits >= Self::bit_width() {
            // Buffer is full
            dst.write_ordered::<Order>(self.byte_buffer).unwrap();
            self.waiting_bits = 0;
            self.byte_buffer = T::zero();
            true
        } else {
            false
        }
    }

    /// Writes up to `bit_width()` bits to the stream. Remembers previously written bits,
    /// and outputs a character to the actual stream once there are
    /// `bit_width()` bits stored in the buffer.
    pub fn write<W: WriteOrdered<T> + ?Sized>(&mut self, dst: &mut W, data: T, size: u32) -> bool {
        assert!(size <= Self::bit_width());

        let new_waiting_bits = self.waiting_bits + size;

        if new_waiting_bits >= Self::bit_width() {
            // Buffer will end up full
            let delta = Self::bit_width() - self.waiting_bits;
            self.waiting_bits = new_waiting_bits % Self::bit_width();

            let out_hi = if delta == Self::bit_width() {
                T::zero()
            } else {
                self.byte_buffer << delta as usize
            };
            dst.write_ordered::<Order>(out_hi | (data >> self.waiting_bits as usize))
                .unwrap();
            self.byte_buffer = data;
            true
        } else {
            self.byte_buffer = (self.byte_buffer << size as usize) | data;
            self.waiting_bits += size;
            false
        }
    }

    /// Flushes remaining bits (if any) to the buffer, completing the byte by
    /// padding with zeroes.
    /// `unchanged` default was `false`
    pub fn flush<W: WriteOrdered<T> + ?Sized>(&mut self, dst: &mut W, unchanged: bool) -> bool {
        if self.waiting_bits != 0 {
            if !unchanged {
                self.byte_buffer =
                    self.byte_buffer << (Self::bit_width() - self.waiting_bits) as usize;
            }
            dst.write_ordered::<Order>(self.byte_buffer).unwrap();
            self.waiting_bits = 0;
            true
        } else {
            false
        }
    }

    pub fn waiting_bits(&self) -> u32 {
        self.waiting_bits
    }
}

impl<T: PrimInt, Order: ByteOrder> Default for OBitStream<T, Order> {
    fn default() -> Self {
        Self::new()
    }
}
