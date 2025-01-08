use anyhow::{bail, Result};
use pgrx::prelude::*;
use serde::Serialize;
use serde_json::Value;

use crate::zkgm::parse_ucs03_zkgm_0;

mod zkgm;

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

#[pg_extern(immutable, parallel_safe)]
fn decode_0_1(input: &[u8], channel_version: &str) -> pgrx::JsonB {
    #[derive(Serialize)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(tag = "code")]
    enum DecodeResult {
        Ok(DecodeOk),
        Error(DecodeError),
    }

    #[derive(Serialize)]
    struct DecodeOk {
        result: Value,
    }

    #[derive(Serialize)]
    struct DecodeError {
        details: ErrorDetails,
    }

    #[derive(Serialize)]
    struct ErrorDetails {
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<String>,
    }

    let result = match channel_version {
        "usc03-zkgm-0" => parse_ucs03_zkgm_0(input),
        _ => Err(
            anyhow::anyhow!("unsupported channel version: {}", channel_version)
                .context("while selecting decoder"),
        ),
    };

    let result = match result {
        Ok(result) => DecodeResult::Ok(DecodeOk { result }),
        Err(err) => DecodeResult::Error(DecodeError {
            details: ErrorDetails {
                message: err.to_string(),
                source: err.source().map(|s| s.to_string()),
            },
        }),
    };

    pgrx::JsonB(serde_json::to_value(result).unwrap())
}

fn decode_from_eth_abi(input: &[u8], extension_format: &str) -> Result<pgrx::JsonB> {
    use alloy_sol_types::{sol, SolType};

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
            json!({"extension": {"forward":{"receiver":"27156Eb671984304ae75Da49aD60C4479B490A06","port":"wasm.union1m37cxl0ld4uaw3r4lv9nt2uw69xxf8xfjrf7a4w9hamv6xvp6ddqqfaaaa","channel":"channel-71","timeout":"0","retries": 0 }},"receiver":"0x01","sender":"0x27156eb671984304ae75da49ad60c4479b490a06","tokens":[{"amount":100,"denom":"0x0e4aaf1351de4c0264c5c7056ef3777b41bd8e03"}]})
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
    fn test_decode_success() {
        let json = decode_0_1(&hex::decode("0b00dd4772d3b8ebf5add472a720f986c0846c9b9c1c0ed98f1a011df8486bfc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014779877a7b0d9e8603169ddbd7836e478b462478900000000000000000000000000000000000000000000000000000000000000000000000000000000000000044c494e4b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f436861696e4c696e6b20546f6b656e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014d1b482d1b947a96e96c9b76d15de34f7f70a20a1000000000000000000000000").unwrap(), "usc03-zkgm-0");

        dbg!(serde_json::to_string(&json.0).unwrap());

        assert_eq!(json.0, json!("zkgm"));
    }

    #[test]
    fn test_decode_error_selecting_decoder() {
        let json = decode_0_1(&hex::decode("0b").unwrap(), "does-not-exist");

        dbg!(serde_json::to_string(&json.0).unwrap());

        assert_eq!(json.0, json!("zkgm"));
    }

    #[test]
    fn test_decode_error_decoding() {
        let json = decode_0_1(&hex::decode("0b").unwrap(), "usc03-zkgm-0");

        dbg!(serde_json::to_string(&json.0).unwrap());

        assert_eq!(json.0, json!("zkgm"));
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
