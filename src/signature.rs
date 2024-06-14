use bucky_crypto::{PublicKeyValue, Signature, SignData};
use bucky_raw_codec::{RawDecode, RawEncode, RawEncodePurpose};
use crate::ObjectLink;

pub const SIGNATURE_REF_INDEX: u8 = 0b_00000000;
pub const SIGNATURE_OBJECT: u8 = 0b_00000001;
pub const SIGNATURE_KEY: u8 = 0b_00000010;

// 1.obj_desc.ref_objs,取值范围为[0, 127]
pub const SIGNATURE_SOURCE_REFINDEX_REF_OBJ_BEGIN: u8 = 0;
pub const SIGNATURE_SOURCE_REFINDEX_REF_OBJ_END: u8 = 127;

/*
2.逻辑ref (从128-255（可以根据需要扩展）
ref[255] = 自己 （适用于有权对象）
ref[254] = owner （使用于有主对象）
ref[253] = author (适用于填写了作者的对象）
ref[252-236] = ood_list[x] (适用于所在Zone的ood对象）
*/
pub const SIGNATURE_SOURCE_REFINDEX_SELF: u8 = 255;
pub const SIGNATURE_SOURCE_REFINDEX_OWNER: u8 = 254;
pub const SIGNATURE_SOURCE_REFINDEX_AUTHOR: u8 = 253;

pub const SIGNATURE_SOURCE_REFINDEX_ZONE_OOD_BEGIN: u8 = 252;
pub const SIGNATURE_SOURCE_REFINDEX_ZONE_OOD_END: u8 = 236;

#[derive(Clone, Eq, PartialEq, Debug, RawEncode, RawDecode)]
pub enum SignatureSource {
    RefIndex(u8),
    Object(ObjectLink),
    Key(PublicKeyValue),
}

impl Default for ObjSignature {
    fn default() -> Self {
        Self {
            sign_source: SignatureSource::RefIndex(0),
            sign_key_index: 0,
            sign: Signature::default(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, RawEncode, RawDecode)]
pub struct ObjSignature {
    sign_source: SignatureSource,
    sign_key_index: u8,
    sign: Signature
}

impl From<(SignatureSource, u8, Signature)> for ObjSignature {
    fn from(value: (SignatureSource, u8, Signature)) -> Self {
        Self {
            sign_source: value.0,
            sign_key_index: value.1,
            sign: value.2
        }
    }
}

impl ObjSignature {
    pub fn new(
        sign_source: SignatureSource,
        sign_key_index: u8,
        sign_time: u64,
        sign: SignData,
    ) -> Self {
        Self {
            sign_source: sign_source,
            sign_key_index,
            sign: Signature::new(sign_time, sign)
        }
    }

    pub fn sign(&self) -> &SignData {
        self.sign.sign()
    }

    pub fn as_slice<'a>(&self) -> &'a [u8] {
        self.sign.as_slice()
    }

    fn sign_source_with_ref_index(&self) -> u8 {
        match self.sign_source {
            SignatureSource::RefIndex(_index) => {
                // sign_key_index[. . . . . . x x] type[. .]
                SIGNATURE_REF_INDEX | (self.sign_key_index << 2)
            }
            SignatureSource::Object(_) => SIGNATURE_OBJECT | (self.sign_key_index << 2),
            SignatureSource::Key(_) => SIGNATURE_KEY,
        }
    }

    pub fn is_ref_index(&self) -> bool {
        match self.sign_source {
            SignatureSource::RefIndex(_) => true,
            _ => false,
        }
    }

    pub fn is_object(&self) -> bool {
        match self.sign_source {
            SignatureSource::Object(_) => true,
            _ => false,
        }
    }

    pub fn is_key(&self) -> bool {
        match self.sign_source {
            SignatureSource::Key(_) => true,
            _ => false,
        }
    }

    pub fn sign_source(&self) -> &SignatureSource {
        &self.sign_source
    }

    pub fn sign_time(&self) -> u64 {
        self.sign.sign_time()
    }

    pub fn sign_key_index(&self) -> u8 {
        self.sign_key_index
    }

    pub fn compare_source(&self, other: &Self) -> bool {
        self.sign_source == other.sign_source && self.sign_key_index == other.sign_key_index
    }

    pub fn signature(&self) -> &Signature {
        &self.sign
    }
}
