use std::fmt;

#[repr(C)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl GUID {
    pub const fn from_bytes(b: &[u8; 16]) -> Self {
        GUID {
            data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            data2: u16::from_le_bytes([b[4], b[5]]),
            data3: u16::from_le_bytes([b[6], b[7]]),
            data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
        }
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&self.data1.to_le_bytes());
        b[4..6].copy_from_slice(&self.data2.to_le_bytes());
        b[6..8].copy_from_slice(&self.data3.to_le_bytes());
        b[8..16].copy_from_slice(&self.data4);
        b
    }
}

impl fmt::Debug for GUID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0], self.data4[1],
            self.data4[2], self.data4[3], self.data4[4], self.data4[5], self.data4[6], self.data4[7],
        )
    }
}

impl PartialEq for GUID {
    fn eq(&self, other: &Self) -> bool {
        self.data1 == other.data1
            && self.data2 == other.data2
            && self.data3 == other.data3
            && self.data4 == other.data4
    }
}

impl Eq for GUID {}

pub const IID_IUNKNOWN: GUID = GUID {
    data1: 0x00000000,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

pub const IID_ICLASSFACTORY: GUID = GUID {
    data1: 0x00000001,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

pub const CLSID_NULL: GUID = GUID {
    data1: 0,
    data2: 0,
    data3: 0,
    data4: [0; 8],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_roundtrip() {
        let g = IID_IUNKNOWN;
        let bytes = g.to_bytes();
        let g2 = GUID::from_bytes(&bytes);
        assert_eq!(g, g2);
    }

    #[test]
    fn guid_debug_format() {
        let s = format!("{:?}", IID_IUNKNOWN);
        assert_eq!(s, "{00000000-0000-0000-C000-000000000046}");
    }

    #[test]
    fn guid_from_bytes_matches_expected() {
        let bytes: [u8; 16] = [
            0x01, 0x14, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ];
        let g = GUID::from_bytes(&bytes);
        assert_eq!(g.data1, 0x00021401);
        assert_eq!(g.data2, 0x0000);
        assert_eq!(g.data3, 0x0000);
    }

    #[test]
    fn clsid_null_is_all_zero() {
        assert_eq!(CLSID_NULL.data1, 0);
        assert_eq!(CLSID_NULL.data2, 0);
        assert_eq!(CLSID_NULL.data3, 0);
        assert_eq!(CLSID_NULL.data4, [0; 8]);
        assert_eq!(CLSID_NULL.to_bytes(), [0u8; 16]);
    }
}
