use alloy_primitives::{keccak256, U256};
use alloy_sol_types::SolValue;
use hex_literal::hex;
use pgrx::pg_extern;
use sha2::{digest::Update, Digest};

/// copy from: https://docs.rs/cosmwasm-std/2.1.4/src/cosmwasm_std/addresses.rs.html#308-317
#[pg_extern(immutable, parallel_safe)]
pub fn instantiate2_0_1(
    intermediate_channel_ids: &[u8],
    receiver_channel_id: i64,
    original_token: &[u8],
    creator: &[u8],
) -> Vec<u8> {
    const CHECKSUM: &[u8; 32] =
        &hex!("B3FA6CECF2E23917CD4D17803C1500D52ABCF3D54286295066C992C9425C8B91");
    assert!(CHECKSUM.len() == 32);

    const MSG: &[u8] = b"";

    let intermediate_channel_ids: U256 = U256::try_from_be_slice(intermediate_channel_ids)
        .expect("cannot convert intermediate_channel_ids to U256"); // handled by pgrx.
    let params = (
        intermediate_channel_ids,
        receiver_channel_id,
        original_token,
    );
    let encoded = params.abi_encode_params();
    let salt: &[u8; 32] = &keccak256(encoded);

    assert!(!salt.is_empty());
    assert!(salt.len() <= 64);

    let mut key = Vec::<u8>::new();
    key.extend_from_slice(b"wasm\0");
    key.extend_from_slice(&(CHECKSUM.len() as u64).to_be_bytes());
    key.extend_from_slice(CHECKSUM);
    key.extend_from_slice(&(creator.len() as u64).to_be_bytes());
    key.extend_from_slice(creator);
    key.extend_from_slice(&(salt.len() as u64).to_be_bytes());
    key.extend_from_slice(salt);
    key.extend_from_slice(&(MSG.len() as u64).to_be_bytes());
    key.extend_from_slice(MSG);
    hash("module", &key)
}

/// The "Basic Address" Hash from
/// https://github.com/cosmos/cosmos-sdk/blob/v0.45.8/docs/architecture/adr-028-public-key-addresses.md
fn hash(ty: &str, key: &[u8]) -> Vec<u8> {
    let inner = sha2::Sha256::digest(ty.as_bytes());
    sha2::Sha256::new()
        .chain(inner)
        .chain(key)
        .finalize()
        .to_vec()
}

#[cfg(any(test, feature = "pg_test"))]
// #[pg_schema]
mod tests {
    use super::*;

    #[test]
    fn test_known_address() {
        // data for this test case obtain from  https://staging.app.union.build/explorer/transfers/0x2E5810EA014F3F16D337C9A268F23945C84DA8A9B36ECF6A618064D8C9EA0606
        let original_token = hex::decode("6d756e6f").unwrap();

        // bech32-decoded: "bbn143365ksyxj0zxj26djqsjltscty75qdlpwry6yxhr8ckzhq92xas8pz8sn"
        let deployer =
            hex::decode("ac63aa5a04349e23495a6c81097d70c2c9ea01bf0b864d10d719f1615c0551bb")
                .unwrap();

        let wrapped_token = instantiate2_0_1(&[], 14, &original_token, &deployer);

        // bech32-decoded & hex decoded: "0x62626e3165397963633737356b7876376b6c7135656839767a6e6a736c70733374717433663274746b753870746b79397171743665636a716e3537307270"
        let expected =
            hex::decode("c9498c7bd4b199eb7c14cdcac14e50f8611581714a96bb70e15d8850017ace24")
                .unwrap();
        assert_eq!(wrapped_token, expected);
    }

    #[test]
    fn test_u256_conversion() {
        assert_decode_encode_equals("0x0");
        assert_decode_encode_equals("0x10203");
        assert_decode_encode_equals("0x1234567890abcdef");
        assert_decode_encode_equals("0xfedcba0987654321");
        assert_decode_encode_equals("0x71afd498d0000");
    }

    fn assert_decode_encode_equals(hex_0x: &str) {
        let hex = &hex_0x[2..];
        let hex_even_nibbles = match hex.len() % 2 == 0 {
            true => hex.to_string(),
            false => format!("0{}", hex),
        };
        let u8_vec = hex::decode(hex_even_nibbles).unwrap();
        let u8_array = u8_vec.as_slice();

        let u256 = U256::try_from_be_slice(u8_array).unwrap();
        let json_value = serde_json::to_value(u256).unwrap();
        let json_string = json_value.as_str().unwrap();

        assert_eq!(hex_0x, json_string);
    }
}
