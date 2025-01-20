use alloy_sol_types::{sol, SolValue};
use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use pgrx::prelude::*;
use serde::Serialize;
use serde_json::Value;
use sha3::{Digest, Keccak256};

mod create3;
mod ucs03_zkgm_0;

pgrx::pg_module_magic!();

/// Attempts to decode a packet into a JSONB. Set throws to `true` to panic on error.
///
/// Valid `rpc_type`s are:
/// - "evm"
/// - "cosmos"
#[pg_extern(immutable, parallel_safe)]
pub fn decode_transfer_packet_0_1(
    input: &[u8],
    rpc_type: &str,
    throws: bool,
    extension_format: &str,
) -> pgrx::JsonB {
    let result = match rpc_type {
        "evm" => decode_from_eth_abi(input, extension_format),
        "cosmos" => decode_from_proto(input, extension_format),
        _ => unimplemented!("only rpc types evm and cosmos are implemented"),
    };

    if throws {
        return result.unwrap();
    }

    result.unwrap_or(pgrx::JsonB(serde_json::Value::Null))
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(tag = "code")]
enum DecodeResult {
    Ok(DecodeResultOk),
    Error(DecodeResultError),
}

#[derive(Serialize)]
#[serde(untagged)]
enum DecodeResultOk {
    Decoded(DecodeOk),
    NoDecoder(NoDecodeOk),
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(tag = "phase")]
enum DecodeResultError {
    Hashing(ErrorDetails),
    Decoding(DecodingError),
}

#[derive(Serialize)]
struct DecodeOk {
    result: Value,
    packet_hash: PacketHash,
}

#[derive(Serialize)]
struct NoDecodeOk {
    packet_hash: PacketHash,
}

#[derive(Serialize)]
struct DecodingError {
    details: ErrorDetails,
    packet_hash: PacketHash,
}

#[derive(Serialize)]
struct ErrorDetails {
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
}

#[pg_extern(immutable, parallel_safe)]
fn decode_ack_0_1(packet: &[u8], ack: &[u8], channel_version: &str) -> pgrx::JsonB {
    let result = match channel_version {
        "ucs03-zkgm-0" => ucs03_zkgm_0::ack::decode(packet, ack),
        _ => Err(
            anyhow::anyhow!("unsupported channel version for: {}", channel_version)
                .context("selecting ack decoder"),
        ),
    };

    let result = match result {
        Ok(result) => DecodeResult::Ok(DecodeResultOk::Decoded(DecodeOk {
            result,
            packet_hash: PacketHash([0; 32]),
        })),
        Err(err) => DecodeResult::Error(DecodeResultError::Decoding(DecodingError {
            details: ErrorDetails {
                message: err.to_string(),
                source: err.source().map(|s| s.to_string()),
            },
            packet_hash: PacketHash([0; 32]),
        })),
    };

    pgrx::JsonB(serde_json::to_value(result).unwrap())
}

#[pg_extern(immutable, parallel_safe)]
fn decode_packet_0_1(packet: &[u8], channel_version: &str) -> pgrx::JsonB {
    let result = match channel_version {
        "ucs03-zkgm-0" => ucs03_zkgm_0::packet::decode(packet),
        _ => Err(
            anyhow::anyhow!("unsupported channel version: {}", channel_version)
                .context("selecting packet decoder"),
        ),
    };

    let result = match result {
        Ok(result) => DecodeResult::Ok(DecodeResultOk::Decoded(DecodeOk {
            result,
            packet_hash: PacketHash([0; 32]),
        })),
        Err(err) => DecodeResult::Error(DecodeResultError::Decoding(DecodingError {
            details: ErrorDetails {
                message: err.to_string(),
                source: err.source().map(|s| s.to_string()),
            },
            packet_hash: PacketHash([0; 32]),
        })),
    };

    pgrx::JsonB(serde_json::to_value(result).unwrap())
}

#[allow(clippy::too_many_arguments)]
#[pg_extern(immutable, parallel_safe)]
fn decode_packet_ack_0_1(
    channel_version: Option<&str>,
    source_channel_id: Option<i32>,
    destination_channel_id: Option<i32>,
    packet: Option<&[u8]>,
    timeout_height: Option<i64>,
    timeout_timestamp: Option<&str>, // would like to use pgrx::AnyNumeric, but this causes linking issues
    ack: Option<&[u8]>,
    mode: Option<&str>,
) -> pgrx::JsonB {
    let decode_result = match hash_packet(
        source_channel_id,
        destination_channel_id,
        packet,
        timeout_height,
        timeout_timestamp,
    ) {
        Ok((packet, packet_hash)) => match &channel_version {
            Some("ucs03-zkgm-0") => {
                match ucs03_zkgm_0::packet_ack::decode(&packet, ack, &packet_hash, mode) {
                    Ok(result) => DecodeResult::Ok(DecodeResultOk::Decoded(DecodeOk {
                        result,
                        packet_hash,
                    })),
                    Err(error) => DecodeResult::Error(DecodeResultError::Decoding(DecodingError {
                        packet_hash,
                        details: ErrorDetails {
                            message: error.to_string(),
                            source: error.source().map(|s| s.to_string()),
                        },
                    })),
                }
            }
            _ => DecodeResult::Ok(DecodeResultOk::NoDecoder(NoDecodeOk { packet_hash })),
        },
        Err(error) => DecodeResult::Error(DecodeResultError::Hashing(ErrorDetails {
            message: format!("error calculating hash: {}", error),
            source: None,
        })),
    };

    pgrx::JsonB(serde_json::to_value(decode_result).unwrap())
}

pub struct PacketHash([u8; 32]);

impl Serialize for PacketHash {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let hex_string = format!("0x{}", hex::encode(self.0)); // Using `hex` crate for hex encoding
        serializer.serialize_str(&hex_string)
    }
}

pub struct PacketPathHash([u8; 32]);

impl PacketPathHash {
    fn to_0x_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

sol! {
    struct Packet {
        uint32 source_channel_id;
        uint32 destination_channel_id;
        bytes data;
        uint64 timeout_height;
        uint64 timeout_timestamp;
    }
}

fn hash_packet(
    source_channel_id: Option<i32>,
    destination_channel_id: Option<i32>,
    packet: Option<&[u8]>,
    timeout_height: Option<i64>,
    timeout_timestamp: Option<&str>,
) -> anyhow::Result<(Packet, PacketHash)> {
    // source: https://github.com/unionlabs/union/blob/main/lib/ibc-solidity/src/lib.rs
    let packet = Packet {
        source_channel_id: source_channel_id
            .ok_or_else(|| anyhow!("source_channel_is is required"))?
            .try_into()
            .context("convert source_channel_id")?,
        destination_channel_id: destination_channel_id
            .ok_or_else(|| anyhow!("destination_channel_id is required"))?
            .try_into()
            .context("convert destination_channel_id")?,
        data: alloy_primitives::Bytes::copy_from_slice(
            packet.ok_or_else(|| anyhow!("packet is required"))?,
        ),
        timeout_height: timeout_height
            .ok_or_else(|| anyhow!("timeout_height is required"))?
            .try_into()
            .context("convert timeout_height")?,
        timeout_timestamp: timeout_timestamp
            .ok_or_else(|| anyhow!("timeout_timestamp is required"))?
            .parse()
            .context("convert timeout_timestamp")?,
    };

    let packet_abi = packet.abi_encode();

    let packet_hash = PacketHash(Keccak256::new().chain_update(packet_abi).finalize().into());

    Ok((packet, packet_hash))
}

fn decode_from_eth_abi(input: &[u8], extension_format: &str) -> Result<pgrx::JsonB> {
    sol! {
        #[derive(Serialize)]
        struct TokenV1 {
            string  denom;
            uint128 amount;
        }

        #[derive(Serialize)]
        struct RelayPacketV1 {
            bytes sender;
            bytes receiver;
            TokenV1[] tokens;
            string extension;
        }

        #[derive(Serialize)]
        struct TokenV2 {
            string  denom;
            uint128 amount;
            uint128 fee;
        }

        #[derive(Serialize)]
        struct RelayPacketV2 {
            bytes sender;
            bytes receiver;
            TokenV2[] tokens;
            string extension;
        }
    }

    let packet = match RelayPacketV2::abi_decode_params(input, false) {
        Err(_) => {
            let v1 = RelayPacketV1::abi_decode_params(input, false)?;
            RelayPacketV2 {
                sender: v1.sender,
                receiver: v1.receiver,
                tokens: v1
                    .tokens
                    .into_iter()
                    .map(|t1| TokenV2 {
                        denom: t1.denom,
                        amount: t1.amount,
                        fee: 0,
                    })
                    .collect(),
                extension: v1.extension,
            }
        }
        Ok(packet) => packet,
    };

    let data = match extension_format {
        "string" => serde_json::to_value(&packet)?,
        "json" => {
            let extension: serde_json::Value = serde_json::from_str(&packet.extension)?;
            let mut packet = serde_json::to_value(&packet)?;
            packet["extension"] = extension;
            packet
        }
        _ => bail!("unknown extension format {extension_format}"),
    };

    Ok(pgrx::JsonB(data))
}

fn decode_from_proto(input: &[u8], extension_format: &str) -> Result<pgrx::JsonB> {
    let mut value: serde_json::Value = serde_json::from_slice(input)?;
    // PFM is sometimes a stringified JSON, in that case we transform it into the JSON object.
    if let Some(extension) = value.get_mut("memo") {
        if extension.is_string() && (extension_format == "json") {
            let payload: serde_json::Value = match serde_json::from_str(extension.as_str().unwrap())
            {
                // Do nothing if we cannot decode.
                Err(_) => return Ok(pgrx::JsonB(value)),
                Ok(payload) => payload,
            };
            *extension = payload;
        }
    }
    Ok(pgrx::JsonB(value))
}

#[cfg(any(test, feature = "pg_test"))]
// #[pg_schema]
mod tests {
    use super::*;
    use base64::prelude::*;
    use serde_json::json;

    #[test]
    fn test_decode_transfer_packet_evm() {
        let data = BASE64_STANDARD.decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCcVbrZxmEMErnXaSa1gxEebSQoGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACoweDBlNGFhZjEzNTFkZTRjMDI2NGM1YzcwNTZlZjM3NzdiNDFiZDhlMDMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMV7ImZvcndhcmQiOnsicmVjZWl2ZXIiOiIyNzE1NkViNjcxOTg0MzA0YWU3NURhNDlhRDYwQzQ0NzlCNDkwQTA2IiwicG9ydCI6Indhc20udW5pb24xbTM3Y3hsMGxkNHVhdzNyNGx2OW50MnV3Njl4eGY4eGZqcmY3YTR3OWhhbXY2eHZwNmRkcXFmYWFhYSIsImNoYW5uZWwiOiJjaGFubmVsLTcxIiwidGltZW91dCI6IjAiLCJyZXRyaWVzIjogMCB9fQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==").unwrap();
        let json = decode_transfer_packet_0_1(&data, "evm", true, "json");
        assert_eq!(
            json.0,
            json!({"extension": {"forward":{"receiver":"27156Eb671984304ae75Da49aD60C4479B490A06","port":"wasm.union1m37cxl0ld4uaw3r4lv9nt2uw69xxf8xfjrf7a4w9hamv6xvp6ddqqfaaaa","channel":"channel-71","timeout":"0","retries": 0 }},"receiver":"0x01","sender":"0x27156eb671984304ae75da49ad60c4479b490a06","tokens":[{"amount":100,"denom":"0x0e4aaf1351de4c0264c5c7056ef3777b41bd8e03","fee":42}]})
        )
    }

    #[test]
    fn test_decode_transfer_packet_cosmos() {
        let json = decode_transfer_packet_0_1(
            &serde_json::to_vec(&json!({"extension": 1})).unwrap(),
            "cosmos",
            true,
            "json",
        );
        assert_eq!(json.0, json!({"extension": 1}));

        let json = decode_transfer_packet_0_1(
            &serde_json::to_vec(&json!({"extension": {"foo": 1}})).unwrap(),
            "cosmos",
            true,
            "json",
        );
        assert_eq!(json.0, json!({"extension": {"foo": 1}}));
    }

    #[test]
    fn test_decode_packet_0_1_success() {
        let json = decode_packet_0_1(&hex::decode("0b00dd4772d3b8ebf5add472a720f986c0846c9b9c1c0ed98f1a011df8486bfc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014779877a7b0d9e8603169ddbd7836e478b462478900000000000000000000000000000000000000000000000000000000000000000000000000000000000000044c494e4b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f436861696e4c696e6b20546f6b656e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014d1b482d1b947a96e96c9b76d15de34f7f70a20a1000000000000000000000000").unwrap(), "ucs03-zkgm-0");

        dbg!(serde_json::to_string(&json.0).unwrap());

        assert_eq!(
            json.0,
            json!({
              "code": "OK",
              "packet_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
              "result": {
                "instruction": {
                  "opcode": 3,
                  "operand": {
                    "_type": "FungibleAssetOrder",
                    "baseAmount": "0x0",
                    "baseToken": "0x779877a7b0d9e8603169ddbd7836e478b4624789",
                    "baseTokenName": "ChainLink Token",
                    "baseTokenPath": "0x0",
                    "baseTokenSymbol": "LINK",
                    "quoteAmount": "0x0",
                    "quoteToken": "0xd1b482d1b947a96e96c9b76d15de34f7f70a20a1",
                    "receiver": "0xe6831e169d77a861a0e71326afa6d80bcc8bc6aa",
                    "sender": "0xe6831e169d77a861a0e71326afa6d80bcc8bc6aa"
                  },
                  "version": 0
                },
                "path": "0x0",
                "salt": "0x0b00dd4772d3b8ebf5add472a720f986c0846c9b9c1c0ed98f1a011df8486bfc"
              }
            })
        );
    }

    #[test]
    fn test_decode_packet_0_1_error_selecting_decoder() {
        let json = decode_packet_0_1(&hex::decode("0b").unwrap(), "does-not-exist");

        dbg!(serde_json::to_string(&json.0).unwrap());

        assert_eq!(
            json.0,
            json!({
              "code": "ERROR",
              "phase": "DECODING",
              "packet_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
              "details": {
                "message": "selecting packet decoder",
                "source": "unsupported channel version: does-not-exist"
              }
            })
        );
    }

    #[test]
    fn test_decode_packet_0_1_error_decoding() {
        let json = decode_packet_0_1(&hex::decode("0b").unwrap(), "ucs03-zkgm-0");

        dbg!(serde_json::to_string(&json.0).unwrap());

        assert_eq!(
            json.0,
            json!({
              "code": "ERROR",
              "phase": "DECODING",
              "packet_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
              "details": {
                "message": "decoding zkgm packet",
                "source": "buffer overrun while deserializing"
              }
            })
        );
    }

    #[test]
    fn test_decode_ack_0_1_success() {
        let json = decode_ack_0_1(&hex::decode("0b00dd4772d3b8ebf5add472a720f986c0846c9b9c1c0ed98f1a011df8486bfc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014779877a7b0d9e8603169ddbd7836e478b462478900000000000000000000000000000000000000000000000000000000000000000000000000000000000000044c494e4b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f436861696e4c696e6b20546f6b656e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014d1b482d1b947a96e96c9b76d15de34f7f70a20a1000000000000000000000000").unwrap(), &hex::decode("0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000B0CAD000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000").unwrap(), "ucs03-zkgm-0");

        dbg!(serde_json::to_string(&json.0).unwrap());

        assert_eq!(
            json.0,
            json!({
              "code": "OK",
              "packet_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
              "result": {
                "innerAck": {
                  "_type": "FungibleAssetOrder",
                  "fillType": "0xb0cad0",
                  "marketMaker": "0x"
                },
                "tag": "0x1"
              }
            })
        );
    }

    #[test]
    fn test_decode_ack_0_1_error_selecting_decoder() {
        let json = decode_ack_0_1(
            &hex::decode("0b").unwrap(),
            &hex::decode("0b").unwrap(),
            "does-not-exist",
        );

        dbg!(serde_json::to_string(&json.0).unwrap());

        assert_eq!(
            json.0,
            json!({
              "code": "ERROR",
              "phase": "DECODING",
              "packet_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
              "details": {
                "message": "selecting ack decoder",
                "source": "unsupported channel version for: does-not-exist"
              }
            })
        );
    }

    #[test]
    fn test_decode_ack_0_1_error_decoding() {
        let json = decode_ack_0_1(
            &hex::decode("0b").unwrap(),
            &hex::decode("0b").unwrap(),
            "ucs03-zkgm-0",
        );

        dbg!(serde_json::to_string(&json.0).unwrap());

        assert_eq!(
            json.0,
            json!({
              "code": "ERROR",
              "phase": "DECODING",
              "packet_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
              "details": {
                "message": "decoding zkgm packet",
                "source": "buffer overrun while deserializing"
              }
            })
        );
    }

    #[test]
    fn test_decode_packet_ack_0_1_success() {
        let json = decode_packet_ack_0_1(
            Some("ucs03-zkgm-0"), 
            Some(1),
            Some(2),
            Some(&hex::decode("0b00dd4772d3b8ebf5add472a720f986c0846c9b9c1c0ed98f1a011df8486bfc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014779877a7b0d9e8603169ddbd7836e478b462478900000000000000000000000000000000000000000000000000000000000000000000000000000000000000044c494e4b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f436861696e4c696e6b20546f6b656e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014d1b482d1b947a96e96c9b76d15de34f7f70a20a1000000000000000000000000").unwrap()), 
            Some(3),
            Some("4"),
            Some(&hex::decode("0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000B0CAD000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000").unwrap()),
            None);
        dbg!(serde_json::to_string(&json.0).unwrap());

        assert_eq!(
            json.0,
            json!({
              "code": "OK",
              "packet_hash": "0xebf016a1ecb0c90eb3274f5881089defd65f7f78ea009271d43d0fbbdd25a8e0",
              "result": {
                "instruction": {
                  "_ack": {
                    "_tag": "0x1",
                    "fillType": "0xb0cad0",
                    "marketMaker": "0x"
                  },
                  "_index": "",
                  "_instruction_hash": "0xb2be16bee56e5e0929d495b7e536f39706fa5624b15160fe31101a9c5ab4d4c1",
                  "opcode": 3,
                  "operand": {
                    "_type": "FungibleAssetOrder",
                    "baseAmount": "0x0",
                    "baseToken": "0x779877a7b0d9e8603169ddbd7836e478b4624789",
                    "baseTokenName": "ChainLink Token",
                    "baseTokenPath": "0x0",
                    "baseTokenSymbol": "LINK",
                    "quoteAmount": "0x0",
                    "quoteToken": "0xd1b482d1b947a96e96c9b76d15de34f7f70a20a1",
                    "receiver": "0xe6831e169d77a861a0e71326afa6d80bcc8bc6aa",
                    "sender": "0xe6831e169d77a861a0e71326afa6d80bcc8bc6aa"
                  },
                  "version": 0
                },
                "path": "0x0",
                "salt": "0x0b00dd4772d3b8ebf5add472a720f986c0846c9b9c1c0ed98f1a011df8486bfc"
              }
            })
        );
    }

    #[test]
    fn test_decode_packet_ack_0_1_error_selecting_decoder() {
        let json = decode_packet_ack_0_1(
            Some("does-not-exist"),
            Some(1),
            Some(2),
            Some(&hex::decode("0b").unwrap()),
            Some(3),
            Some("4"),
            Some(&hex::decode("0b").unwrap()),
            Some("tree"),
        );

        dbg!(serde_json::to_string(&json.0).unwrap());

        assert_eq!(
            json.0,
            json!({
              "code": "OK",
              "packet_hash": "0xb657bbb5a60e97bd758652762aea1e0196985ce624d6f69d84a25d240db045a7"
            })
        );
    }

    #[test]
    fn test_error_missing_value() {
        let json = decode_packet_ack_0_1(
            Some("does-not-exist"),
            Some(1),
            Some(2),
            Some(&hex::decode("0b").unwrap()),
            Some(3),
            None,
            Some(&hex::decode("0b").unwrap()),
            Some("tree"),
        );

        dbg!(serde_json::to_string(&json.0).unwrap());

        assert_eq!(
            json.0,
            json!({
              "code": "ERROR",
              "phase": "HASHING",
              "message": "error calculating hash: timeout_timestamp is required"
            })
        );
    }

    #[test]
    fn test_decode_packet_ack_0_1_error_decoding() {
        let json = decode_packet_ack_0_1(
            Some("ucs03-zkgm-0"),
            Some(1),
            Some(2),
            Some(&hex::decode("0b").unwrap()),
            Some(3),
            Some("4"),
            Some(&hex::decode("0b").unwrap()),
            Some("tree"),
        );

        dbg!(serde_json::to_string(&json.0).unwrap());

        assert_eq!(
            json.0,
            json!({
              "code": "ERROR",
              "phase": "DECODING",
              "details": {
                "message": "decode packet",
                "source": "decoding zkgm packet"
              },
              "packet_hash": "0xb657bbb5a60e97bd758652762aea1e0196985ce624d6f69d84a25d240db045a7"
            })
        );
    }
}

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
