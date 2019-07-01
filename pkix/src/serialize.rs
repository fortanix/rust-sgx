use yasna::{DERWriter, construct_der};
use yasna::models::{ObjectIdentifier, TaggedDerValue};
use num_bigint::{BigInt, BigUint};
use bit_vec::BitVec;

pub trait DerWrite {
    fn write(&self, writer: DERWriter);
}

pub trait ToDer : DerWrite {
    fn to_der(&self) -> Vec<u8> {
        construct_der(|w| self.write(w))
    }
}

impl<T: DerWrite + ?Sized> ToDer for T {}

// uncomment once we have specialization
#[cfg(dont_compile="dont_compile")]
impl<'a, T: DerWrite> DerWrite for &'a T {
    fn write(&self, writer: DERWriter) {
        T::write(self, writer)
    }
}

impl DerWrite for bool {
    fn write(&self, writer: DERWriter) {
        writer.write_bool(*self)
    }
}

impl DerWrite for i64 {
    fn write(&self, writer: DERWriter) {
        writer.write_i64(*self)
    }
}

impl DerWrite for u64 {
    fn write(&self, writer: DERWriter) {
        writer.write_u64(*self)
    }
}

impl DerWrite for i32 {
    fn write(&self, writer: DERWriter) {
        writer.write_i32(*self)
    }
}

impl DerWrite for u32 {
    fn write(&self, writer: DERWriter) {
        writer.write_u32(*self)
    }
}

impl DerWrite for i16 {
    fn write(&self, writer: DERWriter) {
        writer.write_i16(*self)
    }
}

impl DerWrite for u16 {
    fn write(&self, writer: DERWriter) {
        writer.write_u16(*self)
    }
}

impl DerWrite for i8 {
    fn write(&self, writer: DERWriter) {
        writer.write_i8(*self)
    }
}

impl DerWrite for u8 {
    fn write(&self, writer: DERWriter) {
        writer.write_u8(*self)
    }
}

impl DerWrite for BigInt {
    fn write(&self, writer: DERWriter) {
        writer.write_bigint(self)
    }
}

impl DerWrite for BigUint {
    fn write(&self, writer: DERWriter) {
        writer.write_biguint(self)
    }
}

impl DerWrite for ObjectIdentifier {
    fn write(&self, writer: DERWriter) {
        writer.write_oid(self)
    }
}

impl DerWrite for BitVec {
    fn write(&self, writer: DERWriter) {
        writer.write_bitvec(self)
    }
}

impl DerWrite for [u8] {
    fn write(&self, writer: DERWriter) {
        writer.write_bytes(self)
    }
}

impl DerWrite for TaggedDerValue {
    fn write(&self, writer: DERWriter) {
        writer.write_tagged_der(self)
    }
}
