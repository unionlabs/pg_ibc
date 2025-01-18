use std::collections::HashMap;
use std::fmt::Display;

use alloy_sol_types::{sol, SolValue};
use anyhow::{anyhow, Context, Result};
use serde::ser::Error as SerdeError;
use serde::{ser::SerializeStruct, Serialize, Serializer};
use serde_json::{Map, Value};
use sha3::{Digest, Keccak256};

use crate::{Packet, PacketHash, PacketPathHash};

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

pub fn decode(
    packet: &Packet,
    ack: Option<&[u8]>,
    packet_hash: &PacketHash,
    mode: Option<&str>,
) -> Result<Value> {
    let packet_value =
        crate::ucs03_zkgm_0::packet::decode(&packet.data).context("decode packet")?;

    let ack_value_by_path = match ack {
        Some(ack) => find_acks(
            &mut crate::ucs03_zkgm_0::ack::decode(&packet.data, ack).context("decode ack")?,
        )?,
        None => HashMap::new(),
    };

    let mut value = serde_json::to_value(packet_value).context("formatting json")?;

    add_path_and_hash(
        &mut value,
        &ack_value_by_path,
        packet_hash,
        &InstructionPath::new(),
    )?;

    match mode {
        Some("flatten") => Ok(flatten_json_tree(&value)),
        Some(mode) => Err(anyhow!("invalid mode: {mode}")),
        None => Ok(value),
    }
}

fn find_acks(ack: &mut Value) -> Result<HashMap<InstructionPath, Value>> {
    let mut result = HashMap::new();

    add_acks(ack, &InstructionPath::new(), &mut result)?;

    Ok(result)
}

fn add_acks(
    ack: &mut Value,
    instruction_path: &InstructionPath,
    result: &mut HashMap<InstructionPath, Value>,
) -> Result<()> {
    match ack {
        // If it's an object, check for "_type" and process its fields
        Value::Object(map) => {
            for (_, value) in map.iter_mut() {
                let _ = add_acks(value, instruction_path, result);
            }

            if map.contains_key("_type") {
                map.insert(
                    "_index".to_string(),
                    Value::String(instruction_path.to_string()),
                );
                result.insert(instruction_path.clone(), ack.clone());
            }
        }
        // If it's an array, recurse into each element and add index to the path
        Value::Array(arr) => {
            for (index, value) in arr.iter_mut().enumerate() {
                let new_instruction_path = instruction_path.new_with_child(
                    index
                        .try_into()
                        .context(format!("converting index {} from usize to u8", index))?,
                );

                add_acks(value, &new_instruction_path, result)?;
            }
        }
        _ => {} // Do nothing for primitive types
    };

    Ok(())
}

#[derive(Eq, PartialEq, Hash, Clone)]
struct InstructionPath(Vec<u32>);

impl InstructionPath {
    fn new() -> Self {
        Self(vec![])
    }
    fn new_with_child(&self, child: u32) -> Self {
        let mut new_path = self.0.clone();
        new_path.push(child);

        Self(new_path)
    }
}

impl Display for InstructionPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            self.0
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(".")
                .as_str(),
        )
    }
}

fn get_ack_for_path(
    ack_value_by_path: &HashMap<InstructionPath, Value>,
    instruction_path: &InstructionPath,
    expected_type: &String,
) -> Result<Option<Value>> {
    if let Some(ack) = ack_value_by_path.get(instruction_path) {
        if let Value::Object(ack) = ack {
            if let (Some(Value::String(ack_type)), Some(Value::String(ack_index))) =
                (ack.get("_type"), ack.get("_index"))
            {
                // expect type and path to align
                if expected_type != ack_type || &instruction_path.to_string() != ack_index {
                    return Err(anyhow!(
                        "type/index does not align packet type {} <> ack type {} (packet path: {}, ack path: {})",
                        expected_type,
                        ack_type,
                        instruction_path,
                        ack_index
                    ));
                }

                let mut ack = ack.clone();
                ack.remove("_type");
                ack.remove("_index");

                // found a matching ack
                return Ok(Some(Value::Object(ack)));
            } else {
                return Err(anyhow!(
                    "missing type and/or path in path: {instruction_path}"
                ));
            }
        } else {
            return Err(anyhow!("ack in path: {instruction_path} is not an Object"));
        }
    }

    Ok(None)
}

impl PacketHash {
    fn hash_with_path(&self, path: &InstructionPath) -> PacketPathHash {
        let mut hasher = Keccak256::new();

        // Hash the packet hash
        hasher.update(self.0);

        // Hash the path
        hasher.update(path.0.abi_encode());

        PacketPathHash(hasher.finalize().into())
    }
}

fn add_path_and_hash(
    packet: &mut Value,
    ack_value_by_path: &HashMap<InstructionPath, Value>,
    packet_hash: &PacketHash,
    instruction_path: &InstructionPath,
) -> Result<()> {
    match packet {
        // If it's an object, check for "_type" and process its fields
        Value::Object(map) => {
            for (_, value) in map.iter_mut() {
                add_path_and_hash(value, ack_value_by_path, packet_hash, instruction_path)?;
            }

            if let Some(Value::Object(operand)) = map.get("operand") {
                if let Some(Value::String(packet_type)) = operand.get("_type") {
                    if let Some(ack) =
                        get_ack_for_path(ack_value_by_path, instruction_path, packet_type)?
                    {
                        map.insert("_ack".to_string(), ack);
                    }

                    map.insert(
                        "_index".to_string(),
                        Value::String(instruction_path.to_string()),
                    );
                    map.insert(
                        "_instruction_hash".to_string(),
                        Value::String(packet_hash.hash_with_path(instruction_path).to_0x_hex()),
                    );
                }
            }
        }
        // If it's an array, recurse into each element and add index to the path
        Value::Array(arr) => {
            for (index, value) in arr.iter_mut().enumerate() {
                let new_instruction_path = instruction_path.new_with_child(
                    index
                        .try_into()
                        .context(format!("converting index {} from usize to u8", index))?,
                );

                add_path_and_hash(value, ack_value_by_path, packet_hash, &new_instruction_path)?;
            }
        }
        _ => {} // Do nothing for primitive types
    };
    Ok(())
}

pub fn flatten_json_tree(json: &Value) -> Value {
    let mut result = Vec::new();

    // collect root attributes, they will be added to each result entry inside a '_root' element
    let root = match json {
        Value::Object(map) => {
            let mut map = map.clone();
            map.retain(|_, value| !value.is_object());

            Value::Object(map)
        }
        _ => Value::Object(Map::new()),
    };

    flatten_json_tree_recursive(json, &root, &mut result);

    Value::Array(result)
}

fn flatten_json_tree_recursive(json: &Value, root: &Value, result: &mut Vec<Value>) {
    match json {
        Value::Object(map) => {
            if let Some(Value::Object(operand)) = map.get("operand") {
                if operand.contains_key("_type") {
                    // extend the entry with the 'root' properties
                    let mut entry = map.clone();
                    entry.insert("_root".to_string(), root.clone());

                    // Add the current object to the result
                    result.push(Value::Object(entry));
                }
            }

            for value in map.iter().filter_map(|(key, value)| match key.as_str() {
                "_ack" => None, // we don't want to change the ack
                _ => Some(value),
            }) {
                flatten_json_tree_recursive(value, root, result);
            }
        }
        Value::Array(arr) => {
            for value in arr {
                flatten_json_tree_recursive(value, root, result);
            }
        }
        _ => {}
    }
}

#[cfg(any(test, feature = "pg_test"))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_fungible_asset_transfer() {
        let packet = Packet {
            source_channel_id: 1,
            destination_channel_id: 2,
            data: hex::decode("0b00dd4772d3b8ebf5add472a720f986c0846c9b9c1c0ed98f1a011df8486bfc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014779877a7b0d9e8603169ddbd7836e478b462478900000000000000000000000000000000000000000000000000000000000000000000000000000000000000044c494e4b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f436861696e4c696e6b20546f6b656e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014d1b482d1b947a96e96c9b76d15de34f7f70a20a1000000000000000000000000").unwrap().into(),
            timeout_height: 3,
            timeout_timestamp: 4
        };

        let json = decode(&packet, None, &PacketHash([0; 32]), None).unwrap();

        dbg!(serde_json::to_string(&json).unwrap());

        assert_eq!(
            json,
            json!({
              "instruction": {
                "_index": "",
                "_instruction_hash": "0x02ce32bed30842ace78d6dd11b5c473f23a7fe47341f70996d39525428e373ed",
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
    fn test_parse_invalid_data() {
        let packet = Packet {
            source_channel_id: 1,
            destination_channel_id: 2,
            data: hex::decode("00").unwrap().into(),
            timeout_height: 3,
            timeout_timestamp: 4,
        };

        let result = decode(&packet, None, &PacketHash([0; 32]), None);

        assert!(result.is_err());
    }

    use crate::{Packet, PacketHash};

    #[test]
    fn test_batch_ack() {
        let packet = Packet {
            source_channel_id: 1,
            destination_channel_id: 2,
            data: hex::decode("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000560000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000036000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001a0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000014153919669edc8a5d0c8d1e4507c9ce60435a11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014153919669edc8a5d0c8d1e4507c9ce60435a11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014dc7af843e4eb079cd77ace6774bd71d6b8122f07000000000000000000000000000000000000000000000000000000000000000000000000000000000000003a666163746f72792f756e696f6e31327164766d7732326e37326d656d3079736666336e6c796a32633736637579347836306c75612f636c6f776e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000148b4bfb23f4d75feef28b4099c0114e5840d14a4700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000014153919669edc8a5d0c8d1e4507c9ce60435a11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014271126f4f9b36ce16d9e2ef75691485ddce11db60000000000000000000000000000000000000000000000000000000000000000000000000000000000000004cafebabe00000000000000000000000000000000000000000000000000000000").unwrap().into(),
            timeout_height: 3,
            timeout_timestamp: 4
        };

        let ack: &[u8] = &hex::decode("00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000b0cad00000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001").unwrap();

        let json = decode(&packet, Some(ack), &PacketHash([0; 32]), None).unwrap();

        dbg!(serde_json::to_string(&json).unwrap());

        assert_eq!(
            json,
            json!({
              "instruction": {
                "_ack": {
                  "acknowledgements": [
                    {
                      "_index": "0",
                      "_type": "FungibleAssetOrder",
                      "fillType": "0xb0cad0",
                      "marketMaker": "0x"
                    },
                    {
                      "_index": "1",
                      "_type": "Multiplex",
                      "data": "0x0000000000000000000000000000000000000000000000000000000000000001"
                    }
                  ]
                },
                "_index": "",
                "_instruction_hash": "0x02ce32bed30842ace78d6dd11b5c473f23a7fe47341f70996d39525428e373ed",
                "opcode": 2,
                "operand": {
                  "_type": "Batch",
                  "instructions": [
                    {
                      "_ack": {
                        "fillType": "0xb0cad0",
                        "marketMaker": "0x"
                      },
                      "_index": "0",
                      "_instruction_hash": "0x69e40f6af822c360edf576c71482d9bb176e54a4630c0b7ed4194b02df0c30f7",
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
                      "_ack": {
                        "data": "0x0000000000000000000000000000000000000000000000000000000000000001"
                      },
                      "_index": "1",
                      "_instruction_hash": "0xdb2bc9ced66bc9a4e1f66497f5ebe43206c2061cab847b3ed3cb165c4ffad3db",
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
    #[test]

    fn test_batch_ack_without_ack() {
        let packet = Packet {
            source_channel_id: 1,
            destination_channel_id: 2,
            data: hex::decode("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000560000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000036000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001a0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000014153919669edc8a5d0c8d1e4507c9ce60435a11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014153919669edc8a5d0c8d1e4507c9ce60435a11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014dc7af843e4eb079cd77ace6774bd71d6b8122f07000000000000000000000000000000000000000000000000000000000000000000000000000000000000003a666163746f72792f756e696f6e31327164766d7732326e37326d656d3079736666336e6c796a32633736637579347836306c75612f636c6f776e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000148b4bfb23f4d75feef28b4099c0114e5840d14a4700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000014153919669edc8a5d0c8d1e4507c9ce60435a11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014271126f4f9b36ce16d9e2ef75691485ddce11db60000000000000000000000000000000000000000000000000000000000000000000000000000000000000004cafebabe00000000000000000000000000000000000000000000000000000000").unwrap().into(),
            timeout_height: 3,
            timeout_timestamp: 4
        };

        let json = decode(&packet, None, &PacketHash([0; 32]), None).unwrap();

        dbg!(serde_json::to_string(&json).unwrap());

        assert_eq!(
            json,
            json!({
              "instruction": {
                "_index": "",
                "_instruction_hash": "0x02ce32bed30842ace78d6dd11b5c473f23a7fe47341f70996d39525428e373ed",
                "opcode": 2,
                "operand": {
                  "_type": "Batch",
                  "instructions": [
                    {
                      "_index": "0",
                      "_instruction_hash": "0x69e40f6af822c360edf576c71482d9bb176e54a4630c0b7ed4194b02df0c30f7",
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
                      "_index": "1",
                      "_instruction_hash": "0xdb2bc9ced66bc9a4e1f66497f5ebe43206c2061cab847b3ed3cb165c4ffad3db",
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

    #[test]
    fn test_batch_ack_flatten() {
        let packet = Packet {
            source_channel_id: 1,
            destination_channel_id: 2,
            data: hex::decode("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000560000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000036000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001a0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000014153919669edc8a5d0c8d1e4507c9ce60435a11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014153919669edc8a5d0c8d1e4507c9ce60435a11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014dc7af843e4eb079cd77ace6774bd71d6b8122f07000000000000000000000000000000000000000000000000000000000000000000000000000000000000003a666163746f72792f756e696f6e31327164766d7732326e37326d656d3079736666336e6c796a32633736637579347836306c75612f636c6f776e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000148b4bfb23f4d75feef28b4099c0114e5840d14a4700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000014153919669edc8a5d0c8d1e4507c9ce60435a11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014271126f4f9b36ce16d9e2ef75691485ddce11db60000000000000000000000000000000000000000000000000000000000000000000000000000000000000004cafebabe00000000000000000000000000000000000000000000000000000000").unwrap().into(),
            timeout_height: 3,
            timeout_timestamp: 4
        };

        let ack: &[u8] = &hex::decode("00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000b0cad00000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001").unwrap();

        let json = decode(&packet, Some(ack), &PacketHash([0; 32]), Some("flatten")).unwrap();

        dbg!(serde_json::to_string(&json).unwrap());

        assert_eq!(
            json,
            json!([
              {
                "_ack": {
                  "acknowledgements": [
                    {
                      "_index": "0",
                      "_type": "FungibleAssetOrder",
                      "fillType": "0xb0cad0",
                      "marketMaker": "0x"
                    },
                    {
                      "_index": "1",
                      "_type": "Multiplex",
                      "data": "0x0000000000000000000000000000000000000000000000000000000000000001"
                    }
                  ]
                },
                "_index": "",
                "_instruction_hash": "0x02ce32bed30842ace78d6dd11b5c473f23a7fe47341f70996d39525428e373ed",
                "_root": {
                  "path": "0x0",
                  "salt": "0x0000000000000000000000000000000000000000000000000000000000000000"
                },
                "opcode": 2,
                "operand": {
                  "_type": "Batch",
                  "instructions": [
                    {
                      "_ack": {
                        "fillType": "0xb0cad0",
                        "marketMaker": "0x"
                      },
                      "_index": "0",
                      "_instruction_hash": "0x69e40f6af822c360edf576c71482d9bb176e54a4630c0b7ed4194b02df0c30f7",
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
                      "_ack": {
                        "data": "0x0000000000000000000000000000000000000000000000000000000000000001"
                      },
                      "_index": "1",
                      "_instruction_hash": "0xdb2bc9ced66bc9a4e1f66497f5ebe43206c2061cab847b3ed3cb165c4ffad3db",
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
              {
                "_ack": {
                  "fillType": "0xb0cad0",
                  "marketMaker": "0x"
                },
                "_index": "0",
                "_instruction_hash": "0x69e40f6af822c360edf576c71482d9bb176e54a4630c0b7ed4194b02df0c30f7",
                "_root": {
                  "path": "0x0",
                  "salt": "0x0000000000000000000000000000000000000000000000000000000000000000"
                },
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
                "_ack": {
                  "data": "0x0000000000000000000000000000000000000000000000000000000000000001"
                },
                "_index": "1",
                "_instruction_hash": "0xdb2bc9ced66bc9a4e1f66497f5ebe43206c2061cab847b3ed3cb165c4ffad3db",
                "_root": {
                  "path": "0x0",
                  "salt": "0x0000000000000000000000000000000000000000000000000000000000000000"
                },
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
            ])
        );
    }
}
