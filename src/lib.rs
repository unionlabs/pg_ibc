use anyhow::Result;
use pgrx::prelude::*;

pgrx::pg_module_magic!();

/// Attempts to decode a packet into a JSONB. Set throws to `true` to panic on error.
///
/// Valid `rpc_type`s are:
/// - "evm"
/// - "cosmos"
#[pg_extern(immutable, parallel_safe)]
pub fn decode_transfer_packet(input: &[u8], rpc_type: &str, throws: bool) -> pgrx::JsonB {
    let result = match rpc_type {
        "evm" => decode_from_eth_abi(input),
        "cosmos" => decode_from_proto(input),
        _ => unimplemented!("only rpc types evm and cosmos are implemented"),
    };

    if throws {
        return result.unwrap();
    }

    result.unwrap_or(pgrx::JsonB(serde_json::Value::Null))
}

fn decode_from_eth_abi(input: &[u8]) -> Result<pgrx::JsonB> {
    use alloy_sol_types::{sol, SolType};
    use serde::Serialize;

    sol! {
        #[derive(Serialize)]
        struct Token {
            string denom;
            uint128 amount;
        }

        #[derive(Serialize)]
        struct RelayPacket {
            bytes sender;
            bytes receiver;
            Token[] tokens;
            string extension;
        }
    }

    let packet = RelayPacket::abi_decode_params(input, false)?;
    Ok(pgrx::JsonB(serde_json::to_value(&packet)?))
}

fn decode_from_proto(input: &[u8]) -> Result<pgrx::JsonB> {
    let mut value: serde_json::Value = serde_json::from_slice(input)?;
    // PFM is sometimes a stringified JSON, in that case we transform it into the JSON object.
    if let Some(extension) = value.get_mut("extension") {
        if extension.is_string() {
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
        let json = decode_transfer_packet(&data, "evm", true);
        assert_eq!(
            json.0,
            json!({"extension":"{\"forward\":{\"receiver\":\"27156Eb671984304ae75Da49aD60C4479B490A06\",\"port\":\"wasm.union1m37cxl0ld4uaw3r4lv9nt2uw69xxf8xfjrf7a4w9hamv6xvp6ddqqfaaaa\",\"channel\":\"channel-71\",\"timeout\":\"0\",\"retries\": 0 }}","receiver":"0x01","sender":"0x27156eb671984304ae75da49ad60c4479b490a06","tokens":[{"amount":100,"denom":"0x0e4aaf1351de4c0264c5c7056ef3777b41bd8e03"}]})
        )
    }

    #[test]
    fn test_decode_transfer_packet_cosmos() {
        let json = decode_transfer_packet(
            &serde_json::to_vec(&json!({"extension": 1})).unwrap(),
            "cosmos",
            true,
        );
        assert_eq!(json.0, json!({"extension": 1}));

        let json = decode_transfer_packet(
            &serde_json::to_vec(&json!({"extension": "{\"foo\": 1}"})).unwrap(),
            "cosmos",
            true,
        );
        assert_eq!(json.0, json!({"extension": {"foo": 1}}));
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
