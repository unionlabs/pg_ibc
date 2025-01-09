use alloy_sol_types::{private::Bytes, sol, SolType};
use anyhow::{Context, Result};
use serde::ser::Error as SerdeError;
use serde::{ser::SerializeStruct, Serialize, Serializer};
use serde_json::Value;
use crate::hex_0x;

use crate::ucs03_zkgm_0::packet::{Instruction, Operand, ZkgmPacket};

sol! {
    struct Ack {
        uint256 tag;
        bytes innerAck;
    }

    struct BatchAck {
        bytes[] acknowledgements;
    }

    #[derive(Serialize)]
    struct FungibleAssetOrderAck {
        uint256 fillType;
        #[serde(serialize_with = "hex_0x")]
        bytes marketMaker;
    }
}

struct InstructionPacketAck {
    instruction: Instruction,
    ack: Ack,
}

impl Serialize for InstructionPacketAck {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Create a struct with version, opcode, and operand
        let mut state = serializer.serialize_struct("Ack", 2)?;
        state.serialize_field("tag", &self.ack.tag)?;

        let operand = &self
            .instruction
            .decode_operand()
            .map_err(|err| S::Error::custom(format!("error decoding operand (in ack): {err}")))?;

        // Custom serialization for operand based on version and opcode
        let inner_ack = decode_ack(operand, &self.ack.innerAck).unwrap();
        state.serialize_field("innerAck", &inner_ack)?;

        state.end()
    }
}

struct BatchPacketAck {
    instructions: Vec<Instruction>,
    acknowledgements: Vec<Bytes>,
}

impl Serialize for BatchPacketAck {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Create a struct with version, opcode, and operand
        let mut state = serializer.serialize_struct("BatchAck", 2)?;

        if self.instructions.len() != self.acknowledgements.len() {
            return Err(S::Error::custom(format!(
                "instructions count {} <> acknowlegements count {}",
                &self.instructions.len(),
                self.acknowledgements.len()
            )));
        }

        let acknowledgements = self
            .instructions
            .iter()
            .zip(&self.acknowledgements)
            .enumerate()
            .map(|(index, (instruction, ack))| {
                let ack = <Ack>::abi_decode_sequence(ack, false)
                    .context(format!("decoding ack packet {index}"))?;

                Ok(InstructionPacketAck {
                    instruction: instruction.clone(),
                    ack,
                })
            })
            .collect::<Result<Vec<_>>>()
            .map_err(|err| S::Error::custom(format!("error batch acks: {err}")))?;

        state.serialize_field("acknowledgements", &acknowledgements)?;

        state.end()
    }
}

fn decode_ack(operand: &Operand, ack: &Bytes) -> Result<InnerAck> {
    Ok(match operand {
        Operand::Forward(forward) => InnerAck::Forward(InstructionPacketAck {
            instruction: forward.instruction.clone(),
            ack: <Ack>::abi_decode_sequence(ack, false).context("decoding forward ack")?,
        }),
        Operand::Multiplex(_) => InnerAck::Multiplex { data: ack.clone() },
        Operand::Batch(batch) => InnerAck::Batch(BatchPacketAck {
            instructions: batch.instructions.clone(),
            acknowledgements: <BatchAck>::abi_decode_sequence(ack, false)
                .context("decoding BatchAck")?
                .acknowledgements,
        }),
        Operand::FungibleAssetOrder(_) => InnerAck::FungibleAssetOrder(
            <FungibleAssetOrderAck>::abi_decode_sequence(ack, false)
                .context("decoding FungibleAssetOrderAck")?,
        ),
        Operand::Unsupported { data: _ } => InnerAck::Unsupported { data: ack.clone() },
    })
}

#[derive(Serialize)]
#[serde(tag = "_type")]
enum InnerAck {
    Forward(InstructionPacketAck),
    Multiplex { 
        #[serde(serialize_with = "hex_0x")]
        data: Bytes 
    },
    Batch(BatchPacketAck),
    FungibleAssetOrder(FungibleAssetOrderAck),
    Unsupported { 
        #[serde(serialize_with = "hex_0x")]
        data: Bytes 
    },
}

pub fn decode(packet: &[u8], ack: &[u8]) -> Result<Value> {
    let instruction = <ZkgmPacket>::abi_decode_sequence(packet, false)
        .context("decoding zkgm packet")?
        .instruction;
    let ack = <Ack>::abi_decode_sequence(ack, false).context("decoding ack packet")?;

    let instruction_ack = InstructionPacketAck { instruction, ack };

    let value = serde_json::to_value(&instruction_ack).context("formatting json")?;

    Ok(value)
}

#[cfg(any(test, feature = "pg_test"))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_fungible_asset_transfer_ack() {
        let json = decode(&hex::decode("0B00DD4772D3B8EBF5ADD472A720F986C0846C9B9C1C0ED98F1A011DF8486BFC0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002C00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001C000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014E6831E169D77A861A0E71326AFA6D80BCC8BC6AA0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014E6831E169D77A861A0E71326AFA6D80BCC8BC6AA0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014779877A7B0D9E8603169DDBD7836E478B462478900000000000000000000000000000000000000000000000000000000000000000000000000000000000000044C494E4B00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000F436861696E4C696E6B20546F6B656E00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014D1B482D1B947A96E96C9B76D15DE34F7F70A20A1000000000000000000000000").unwrap(),&hex::decode("0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000B0CAD000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000").unwrap()).unwrap();

        dbg!(serde_json::to_string(&json).unwrap());

        assert_eq!(
            json,
            json!({
              "innerAck": {
                "_type": "FungibleAssetOrder",
                "fillType": "0xb0cad0",
                "marketMaker": "0x"
              },
              "tag": "0x1"
            })
        );
    }
}
