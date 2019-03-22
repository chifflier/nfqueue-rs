use std::fmt;

/// Hardware (Ethernet) address
pub struct HwAddr<'a> {
    _hw: &'a [u8],
}

impl<'a> HwAddr<'a> {
    pub fn new(s: &'a [u8]) -> HwAddr<'a> {
        HwAddr { _hw: s }
    }
}

impl<'a> fmt::Display for HwAddr<'a> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self._hw.iter().fold(String::new(), |acc, &b| {
            (if !acc.is_empty() { acc + ":" } else { acc }) + &format!("{:02x}", b)
        });
        return write!(out, "{}", s);
    }
}
