//! Bounds-checked little-endian readers and writers for received frames.

use core::fmt;

/// Everything that can go wrong reading a frame. Deliberately coarse: the
/// caller's only sane response to any of these is to drop the frame and, if it
/// keeps happening, drop the connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireError {
    /// Ran off the end of the buffer.
    Short,
    /// The message id is not one this build knows.
    UnknownMessage(u8),
    /// A count or index outside the range the protocol allows.
    Range,
    /// The writer was handed a buffer too small for the message.
    NoRoom,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Short => f.write_str("frame ended early"),
            WireError::UnknownMessage(id) => write!(f, "unknown message 0x{id:02x}"),
            WireError::Range => f.write_str("value out of range"),
            WireError::NoRoom => f.write_str("output buffer too small"),
        }
    }
}

/// A read cursor over a received frame.
pub struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, at: 0 }
    }

    /// How many bytes are still unread. Callers use this to decide whether a
    /// trailing entry is present rather than trusting a count field.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.at
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.at >= self.buf.len()
    }

    #[inline]
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.at.checked_add(n).ok_or(WireError::Short)?;
        if end > self.buf.len() {
            return Err(WireError::Short);
        }
        let s = &self.buf[self.at..end];
        self.at = end;
        Ok(s)
    }

    #[inline]
    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    #[inline]
    pub fn i8(&mut self) -> Result<i8, WireError> {
        Ok(self.u8()? as i8)
    }

    #[inline]
    pub fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    #[inline]
    pub fn i16(&mut self) -> Result<i16, WireError> {
        Ok(self.u16()? as i16)
    }

    #[inline]
    pub fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[inline]
    pub fn f32(&mut self) -> Result<f32, WireError> {
        Ok(f32::from_bits(self.u32()?))
    }

    /// An `f32` that is required to be a real number.
    ///
    /// A NaN reaching the simulation is worse than a dropped frame: it
    /// propagates through every interpolation it touches and does not come
    /// back. Positions arrive through here, not through [`Reader::f32`].
    #[inline]
    pub fn f32_finite(&mut self) -> Result<f32, WireError> {
        let v = self.f32()?;
        if v.is_finite() {
            Ok(v)
        } else {
            Err(WireError::Range)
        }
    }
}

/// A write cursor over a caller-owned buffer.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf, at: 0 }
    }

    /// Bytes written so far. This is the length to hand to the socket.
    #[inline]
    pub fn len(&self) -> usize {
        self.at
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.at == 0
    }

    #[inline]
    fn room(&mut self, n: usize) -> Result<&mut [u8], WireError> {
        let end = self.at.checked_add(n).ok_or(WireError::NoRoom)?;
        if end > self.buf.len() {
            return Err(WireError::NoRoom);
        }
        let s = &mut self.buf[self.at..end];
        self.at = end;
        Ok(s)
    }

    #[inline]
    pub fn u8(&mut self, v: u8) -> Result<(), WireError> {
        self.room(1)?[0] = v;
        Ok(())
    }

    #[inline]
    pub fn i8(&mut self, v: i8) -> Result<(), WireError> {
        self.u8(v as u8)
    }

    #[inline]
    pub fn u16(&mut self, v: u16) -> Result<(), WireError> {
        self.room(2)?.copy_from_slice(&v.to_le_bytes());
        Ok(())
    }

    #[inline]
    pub fn i16(&mut self, v: i16) -> Result<(), WireError> {
        self.u16(v as u16)
    }

    #[inline]
    pub fn u32(&mut self, v: u32) -> Result<(), WireError> {
        self.room(4)?.copy_from_slice(&v.to_le_bytes());
        Ok(())
    }

    /// A position or an arc length.
    ///
    /// Non-finite input is written as zero rather than refused. The encoder is
    /// on the trusted side of the boundary, so a NaN here is a bug in our own
    /// simulation - and dropping the whole frame over it would take the other
    /// three cars off the screen to punish one bad float.
    #[inline]
    pub fn f32(&mut self, v: f32) -> Result<(), WireError> {
        let clean = if v.is_finite() { v } else { 0.0 };
        self.u32(clean.to_bits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_what_was_written() {
        let mut buf = [0u8; 32];
        let n = {
            let mut w = Writer::new(&mut buf);
            w.u8(0x81).unwrap();
            w.u16(40_000).unwrap();
            w.i16(-1234).unwrap();
            w.u32(0xDEAD_BEEF).unwrap();
            w.f32(-12.5).unwrap();
            w.len()
        };
        let mut r = Reader::new(&buf[..n]);
        assert_eq!(r.u8().unwrap(), 0x81);
        assert_eq!(r.u16().unwrap(), 40_000);
        assert_eq!(r.i16().unwrap(), -1234);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.f32().unwrap(), -12.5);
        assert!(r.is_empty());
    }

    #[test]
    fn short_buffer_is_an_error_not_a_panic() {
        let buf = [1u8, 2];
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u32(), Err(WireError::Short));
    }

    #[test]
    fn a_full_writer_refuses_rather_than_overruns() {
        let mut buf = [0u8; 3];
        let mut w = Writer::new(&mut buf);
        w.u16(1).unwrap();
        assert_eq!(w.u32(0), Err(WireError::NoRoom));
    }

    #[test]
    fn nan_never_reaches_the_simulation() {
        let mut buf = [0u8; 8];
        let n = {
            let mut w = Writer::new(&mut buf);
            // hand-write the bit pattern the encoder would refuse to produce
            w.u32(f32::NAN.to_bits()).unwrap();
            w.len()
        };
        let mut r = Reader::new(&buf[..n]);
        assert_eq!(r.f32_finite(), Err(WireError::Range));
    }
}
