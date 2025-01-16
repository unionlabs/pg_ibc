use alloy_sol_types::{sol, SolType};
use anyhow::{Context, Result};
use serde::ser::Error as SerdeError;
use serde::{ser::SerializeStruct, Serialize, Serializer};
use serde_json::Value;

// source: github:unionlabs/union/evm/contracts/apps/ucs/03-zkgm/Zkgm.sol
const OP_FORWARD: u8 = 0x00;
const OP_MULTIPLEX: u8 = 0x01;
const OP_BATCH: u8 = 0x02;
const OP_FUNGIBLE_ASSET_TRANSFER: u8 = 0x03;

sol! {
    #[derive(Serialize)]
    struct ZkgmPacket {
        bytes32 salt;
        uint256 path;
        Instruction instruction;
    }

    #[derive(Debug)]
    struct Instruction {
        uint8 version;
        uint8 opcode;
        bytes operand;
    }

    #[derive(Serialize)]
    struct Forward {
        uint32 channelId;
        uint64 timeoutHeight;
        uint64 timeoutTimestamp;
        Instruction instruction;
    }

    #[derive(Serialize)]
    struct Multiplex {
        bytes sender;
        bool eureka;
        bytes contractAddress;
        bytes contractCalldata;
    }

    #[derive(Serialize)]
    struct Batch {
        Instruction[] instructions;
    }

    #[derive(Serialize)]
    struct FungibleAssetOrder {
        bytes sender;
        bytes receiver;
        bytes baseToken;
        uint256 baseAmount;
        string baseTokenSymbol;
        string baseTokenName;
        uint256 baseTokenPath;
        bytes quoteToken;
        uint256 quoteAmount;
    }
}

impl Serialize for Instruction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Create a struct with version, opcode, and operand
        let mut state = serializer.serialize_struct("Instruction", 3)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("opcode", &self.opcode)?;

        // Custom serialization for operand based on version and opcode
        let modified_operand = &self.decode_operand().map_err(|err| {
            S::Error::custom(format!("error decoding operand (in packet): {err}"))
        })?;
        state.serialize_field("operand", &modified_operand)?;

        state.end()
    }
}

impl Instruction {
    pub fn decode_operand(&self) -> Result<Operand> {
        Ok(match (self.version, self.opcode) {
            (0, OP_FORWARD) => Operand::Forward(
                <Forward>::abi_decode_sequence(&self.operand, false).context("decoding Forward")?,
            ),
            (0, OP_MULTIPLEX) => Operand::Multiplex(
                <Multiplex>::abi_decode_sequence(&self.operand, false)
                    .context("decoding Multiplex")?,
            ),
            (0, OP_BATCH) => Operand::Batch(
                <Batch>::abi_decode_sequence(&self.operand, false).context("decoding Batch")?,
            ),
            (0, OP_FUNGIBLE_ASSET_TRANSFER) => Operand::FungibleAssetOrder(
                <FungibleAssetOrder>::abi_decode_sequence(&self.operand, false)
                    .context("decoding FungibleAssetOrder")?,
            ),
            _ => Operand::Unsupported {
                data: self.operand.clone(),
            },
        })
    }
}

#[derive(Serialize)]
#[serde(tag = "_type")]
pub enum Operand {
    Forward(Forward),
    Multiplex(Multiplex),
    Batch(Batch),
    FungibleAssetOrder(FungibleAssetOrder),
    Unsupported {
        data: alloy_sol_types::private::Bytes,
    },
}

pub fn decode(input: &[u8]) -> Result<Value> {
    let zkgm_packet =
        <ZkgmPacket>::abi_decode_sequence(input, false).context("decoding zkgm packet")?;

    let value = serde_json::to_value(&zkgm_packet).context("formatting json")?;

    Ok(value)
}

#[cfg(any(test, feature = "pg_test"))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_ucs03_zkgm_0_with_fungible_asset_transfer_packet() {
        let json = decode(&hex::decode("0b00dd4772d3b8ebf5add472a720f986c0846c9b9c1c0ed98f1a011df8486bfc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014779877a7b0d9e8603169ddbd7836e478b462478900000000000000000000000000000000000000000000000000000000000000000000000000000000000000044c494e4b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f436861696e4c696e6b20546f6b656e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014d1b482d1b947a96e96c9b76d15de34f7f70a20a1000000000000000000000000").unwrap()).unwrap();

        dbg!(serde_json::to_string(&json).unwrap());

        assert_eq!(
            json,
            json!({
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
            })
        );
    }

    #[test]
    fn test_parse_ucs03_zkgm_0_with_xyz() {
        let result = decode(&hex::decode("00").unwrap());

        assert!(result.is_err());
    }

    #[test]
    fn test_batch() {
        let json = decode(&hex::decode("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000560000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000036000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001a0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000014153919669edc8a5d0c8d1e4507c9ce60435a11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014153919669edc8a5d0c8d1e4507c9ce60435a11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014dc7af843e4eb079cd77ace6774bd71d6b8122f07000000000000000000000000000000000000000000000000000000000000000000000000000000000000003a666163746f72792f756e696f6e31327164766d7732326e37326d656d3079736666336e6c796a32633736637579347836306c75612f636c6f776e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000148b4bfb23f4d75feef28b4099c0114e5840d14a4700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000014153919669edc8a5d0c8d1e4507c9ce60435a11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014271126f4f9b36ce16d9e2ef75691485ddce11db60000000000000000000000000000000000000000000000000000000000000000000000000000000000000004cafebabe00000000000000000000000000000000000000000000000000000000").unwrap()).unwrap();

        dbg!(serde_json::to_string(&json).unwrap());

        assert_eq!(
            json,
            json!({
                "instruction": {
                  "opcode": 2,
                  "operand": {
                    "_type": "Batch",
                    "instructions": [
                      {
                        "opcode": 3,
                        "operand": {
                          "_type": "FungibleAssetOrder",
                          "baseAmount": "0x1",
                          "baseToken": "0xdc7af843e4eb079cd77ace6774bd71d6b8122f07",
                          "baseTokenName": "",
                          "baseTokenPath": "0x0",
                          "baseTokenSymbol": "factory/union12qdvmw22n72mem0ysff3nlyj2c76cuy4x60lua/clown",
                          "quoteAmount": "0x1",
                          "quoteToken": "0x8b4bfb23f4d75feef28b4099c0114e5840d14a47",
                          "receiver": "0x153919669edc8a5d0c8d1e4507c9ce60435a1177",
                          "sender": "0x153919669edc8a5d0c8d1e4507c9ce60435a1177"
                        },
                        "version": 0
                      },
                      {
                        "opcode": 1,
                        "operand": {
                          "_type": "Multiplex",
                          "contractAddress": "0x271126f4f9b36ce16d9e2ef75691485ddce11db6",
                          "contractCalldata": "0xcafebabe",
                          "eureka": true,
                          "sender": "0x153919669edc8a5d0c8d1e4507c9ce60435a1177"
                        },
                        "version": 0
                      }
                    ]
                  },
                  "version": 0
                },
                "path": "0x0",
                "salt": "0x0000000000000000000000000000000000000000000000000000000000000000"
              })
        );
    }
}
