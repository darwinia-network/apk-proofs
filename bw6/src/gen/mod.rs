pub mod asig;
pub mod domain;
pub mod packed_proof;
pub mod pks_comm;
pub mod public_input;
pub mod rvk;
pub mod simple_proof;

pub use self::asig::*;
pub use self::domain::*;
pub use self::packed_proof::*;
pub use self::pks_comm::*;
pub use self::public_input::*;
pub use self::rvk::*;
pub use self::simple_proof::*;

use ark_ff::BigInteger;
use ark_ff::PrimeField;
use serde::Serialize;
use serde_hex::{SerHexSeq, StrictPfx};

#[derive(Serialize)]
struct Uint512 {
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    a: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    b: Vec<u8>,
}

#[derive(Serialize)]
struct Uint768 {
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    a: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    b: Vec<u8>,
    #[serde(with = "SerHexSeq::<StrictPfx>")]
    c: Vec<u8>,
}

#[derive(Serialize)]
struct Bw6G1 {
    x: Uint768,
    y: Uint768,
}

#[derive(Serialize)]
struct Bw6G2 {
    x: Uint768,
    y: Uint768,
}

#[derive(Serialize)]
struct Bls12G1 {
    x: Uint512,
    y: Uint512,
}

#[derive(Serialize)]
struct Bls12G2 {
    x: Bls12Fp2,
    y: Bls12Fp2,
}

#[derive(Serialize)]
struct Bls12Fp2 {
    c0: Uint512,
    c1: Uint512,
}

impl Uint512 {
    pub fn from(bytes: Vec<u8>) -> Self {
        let (h, l) = bytes.split_at(bytes.len() - 32);
        Uint512 {
            a: h.to_vec(),
            b: l.to_vec(),
        }
    }

    pub fn from_fr(fr: ark_bw6_761::Fr) -> Self {
        let bytes = fr.into_bigint().to_bytes_be();
        let (h, l) = bytes.split_at(bytes.len() - 32);
        Uint512 {
            a: h.to_vec(),
            b: l.to_vec(),
        }
    }
}

impl Uint768 {
    pub fn from(bytes: Vec<u8>) -> Self {
        let (t, l) = bytes.split_at(bytes.len() - 32);
        let (h, m) = t.split_at(t.len() - 32);
        Uint768 {
            a: h.to_vec(),
            b: m.to_vec(),
            c: l.to_vec(),
        }
    }
}

impl Bw6G1 {
    pub fn from(g1: ark_bw6_761::G1Affine) -> Self {
        let x = g1.x.into_bigint().to_bytes_be();
        let y = g1.y.into_bigint().to_bytes_be();
        Bw6G1 {
            x: Uint768::from(x),
            y: Uint768::from(y),
        }
    }
}

impl Bw6G2 {
    pub fn from(g2: ark_bw6_761::G2Affine) -> Self {
        let x = g2.x.into_bigint().to_bytes_be();
        let y = g2.y.into_bigint().to_bytes_be();
        Bw6G2 {
            x: Uint768::from(x),
            y: Uint768::from(y),
        }
    }
}

impl Bls12G1 {
    pub fn from(g1: ark_bls12_377::G1Affine) -> Self {
        let x = g1.x.into_bigint().to_bytes_be();
        let y = g1.y.into_bigint().to_bytes_be();
        Bls12G1 {
            x: Uint512::from(x),
            y: Uint512::from(y),
        }
    }
}

impl Bls12G2 {
    pub fn from(g2: ark_bls12_377::G2Affine) -> Self {
        let x_c0 = g2.x.c0.into_bigint().to_bytes_be();
        let x_c1 = g2.x.c1.into_bigint().to_bytes_be();
        let x = Bls12Fp2 {
            c0: Uint512::from(x_c0),
            c1: Uint512::from(x_c1),
        };
        let y_c0 = g2.y.c0.into_bigint().to_bytes_be();
        let y_c1 = g2.y.c1.into_bigint().to_bytes_be();
        let y = Bls12Fp2 {
            c0: Uint512::from(y_c0),
            c1: Uint512::from(y_c1),
        };
        Bls12G2 { x, y }
    }
}
