//! `ReadOrdered` and `WriteOrdered` say that a type can be read from/written to
//! with integers of a certain size in either byte ordering.
//! 
//! The traits `ReadOrdered` and `WriteOrdered` are implemented
//! for any type that implements `Read` and `Write` (respectively) for all of the common
//! integer types, so it **does not need to be implemented by the user**

use num_traits::PrimInt;
use byteorder::{ReadBytesExt, WriteBytesExt, ByteOrder};

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

