use sm3::{Digest, Sm3};
use sm3::digest::Output;

const BLOCK_LENGTH: usize = 64;
const SM3_OUTPUT_LENGTH: usize = 32;

pub struct HmacSm3 {
    opad: [u8; BLOCK_LENGTH],
    sm3: Sm3,
}

impl HmacSm3 {
    pub fn new(key: &[u8]) -> Self {
        let mut structured_key = vec![0_u8; BLOCK_LENGTH];
        if key.len() > BLOCK_LENGTH {
            structured_key[0..SM3_OUTPUT_LENGTH].copy_from_slice(sm3_digest(&key).as_slice());
        } else {
            structured_key[0..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36_u8; BLOCK_LENGTH];
        let mut opad = [0x5c_u8; BLOCK_LENGTH];
        for i in 0..BLOCK_LENGTH {
            ipad[i] ^= structured_key[i];
            opad[i] ^= structured_key[i];
        }

        let mut sm3 = Sm3::new();
        sm3.update(&ipad);
        Self {
            opad,
            sm3,
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        self.sm3.update(message);
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        let ipad_message_digest = self.sm3.clone().finalize();
        let mut opad_ipad_message_digest = self.opad.to_vec();
        opad_ipad_message_digest.extend_from_slice(ipad_message_digest.as_slice());
        sm3_digest(&opad_ipad_message_digest).as_slice().to_vec()
    }
}

pub fn hmac_sm3(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut hsm3 = HmacSm3::new(key);
    hsm3.update(message);
    hsm3.finalize()
}

fn sm3_digest(message: &[u8]) -> Output<Sm3> {
    let mut sm3 = Sm3::new();
    sm3.update(&message);
    sm3.finalize()
}

#[test]
fn test_001() {
    let message = b"Hello World";
    let key = b"TestSecret";

    let hmac1 = hmac_sm3(key, message);
    assert_eq!("9d91da552268ddf11b9f69662773a66c6375b250336dfb9293e7e2611c36d79f", hex::encode(hmac1));

    let mut hm = HmacSm3::new(key);
    hm.update(b"Hello");
    hm.update(b" ");
    hm.update(b"World");
    let hmac2 = hm.finalize();
    assert_eq!("9d91da552268ddf11b9f69662773a66c6375b250336dfb9293e7e2611c36d79f", hex::encode(hmac2));
}


#[test]
fn test_002() {
    let message = b"Hello World";
    let key = b"TestSecretTestSecretTestSecretTestSecretTestSecretTestSecretTestSecretTestSecretTestSecretTest";

    let hmac1 = hmac_sm3(key, message);
    assert_eq!("ee3a9564211308bd5ca5b428b3de8a2494bb731b55d7169c60907f0e2045649d", hex::encode(hmac1));

    let mut hm = HmacSm3::new(key);
    hm.update(b"Hello");
    hm.update(b" ");
    hm.update(b"World");
    let hmac2 = hm.finalize();
    assert_eq!("ee3a9564211308bd5ca5b428b3de8a2494bb731b55d7169c60907f0e2045649d", hex::encode(hmac2));
}

