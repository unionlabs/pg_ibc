use alloy_primitives::Uint;
use alloy_sol_types::{sol, SolType};
use anyhow::{Context, Result};
use serde::Serialize;
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

    #[derive(Serialize)]
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

#[derive(Serialize)]
struct ParsedZkgmPacket {
    pub salt: alloy_primitives::FixedBytes<32>,
    pub path: Uint<256, 4>,
    pub instruction: ParsedInstruction,
}

impl TryFrom<ZkgmPacket> for ParsedZkgmPacket {
    type Error = anyhow::Error;

    fn try_from(value: ZkgmPacket) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            salt: value.salt,
            path: value.path,
            instruction: value
                .instruction
                .try_into()
                .context("decoding ZkgmPacket.instruction")?,
        })
    }
}

#[derive(Serialize)]
struct ParsedInstruction {
    pub version: u8,
    pub opcode: u8,
    pub operand: ParsedOperand,
}

impl TryFrom<Instruction> for ParsedInstruction {
    type Error = anyhow::Error;

    fn try_from(value: Instruction) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            version: value.version,
            opcode: value.opcode,
            operand: decode_operand(value.version, value.opcode, value.operand)
                .context("decoding Instruction.operand")?,
        })
    }
}

#[derive(Serialize)]
struct ParsedForward {
    pub channel_id: u32,
    pub timeout_height: u64,
    pub timeout_timestamp: u64,
    pub instruction: Box<ParsedInstruction>,
}

impl TryFrom<Forward> for ParsedForward {
    type Error = anyhow::Error;

    fn try_from(value: Forward) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            channel_id: value.channelId,
            timeout_height: value.timeoutHeight,
            timeout_timestamp: value.timeoutTimestamp,
            instruction: Box::new(
                value
                    .instruction
                    .try_into()
                    .context("parsing ForwardPacket.instruction")?,
            ),
        })
    }
}

#[derive(Serialize)]
struct ParsedBatch {
    pub instructions: Vec<ParsedInstruction>,
}

impl TryFrom<Batch> for ParsedBatch {
    type Error = anyhow::Error;

    fn try_from(value: Batch) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            instructions: value
                .instructions
                .into_iter()
                .enumerate()
                .map(|(index, instruction)| {
                    instruction
                        .clone()
                        .try_into()
                        .context(format!("parsing BatchPacket.instructions[{index}]"))
                })
                .collect::<Result<_>>()?,
        })
    }
}

fn decode_operand(
    version: u8,
    index: u8,
    packet: alloy_sol_types::private::Bytes,
) -> Result<ParsedOperand> {
    Ok(match (version, index) {
        (0, OP_FORWARD) => ParsedOperand::Forward(
            <Forward>::abi_decode_sequence(&packet, false)
                .context("decoding Forward")?
                .try_into()
                .context("parsing Forward")?,
        ),
        (0, OP_MULTIPLEX) => ParsedOperand::Multiplex(
            <Multiplex>::abi_decode_sequence(&packet, false).context("decoding ForwardPacket")?,
        ),
        (0, OP_BATCH) => ParsedOperand::Batch(
            <Batch>::abi_decode_sequence(&packet, false)
                .context("decoding BatchPacket")?
                .try_into()
                .context("parsing BatchPacket")?,
        ),
        (0, OP_FUNGIBLE_ASSET_TRANSFER) => ParsedOperand::FungibleAssetOrder(
            <FungibleAssetOrder>::abi_decode_sequence(&packet, false)
                .context("decoding FungibleAssetOrder")?,
        ),
        _ => ParsedOperand::Unsupported(packet),
    })
}

#[derive(Serialize)]
#[serde(tag = "_type")]
enum ParsedOperand {
    Forward(ParsedForward),
    Multiplex(Multiplex),
    Batch(ParsedBatch),
    FungibleAssetOrder(FungibleAssetOrder),
    Unsupported(alloy_sol_types::private::Bytes),
}

pub fn parse_ucs03_zkgm_0(input: &[u8]) -> Result<Value> {
    let zkgm_packet =
        <ZkgmPacket>::abi_decode_sequence(input, false).context("decoding zkgm packet")?;

    let parsed_zkgm_packet: ParsedZkgmPacket = zkgm_packet.try_into().context("parsing packet")?;

    let value = serde_json::to_value(&parsed_zkgm_packet).context("formatting json")?;

    Ok(value)
}

#[cfg(any(test, feature = "pg_test"))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_ucs03_zkgm_0_with_fungible_asset_transfer_packet() {
        let json = parse_ucs03_zkgm_0(&hex::decode("0b00dd4772d3b8ebf5add472a720f986c0846c9b9c1c0ed98f1a011df8486bfc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e6831e169d77a861a0e71326afa6d80bcc8bc6aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014779877a7b0d9e8603169ddbd7836e478b462478900000000000000000000000000000000000000000000000000000000000000000000000000000000000000044c494e4b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f436861696e4c696e6b20546f6b656e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014d1b482d1b947a96e96c9b76d15de34f7f70a20a1000000000000000000000000").unwrap()).unwrap();

        dbg!(serde_json::to_string(&json).unwrap());

        assert_eq!(json, json!("zkgm"));
    }

    #[test]
    fn test_parse_ucs03_zkgm_0_with_xyz() {
        let json = parse_ucs03_zkgm_0(&hex::decode("00000000000000000000000000000000000000000000000000000000000000FF00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000034000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002C00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001C0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000000000000000000000A0000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014153919669EDC8A5D0C8D1E4507C9CE60435A11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014153919669EDC8A5D0C8D1E4507C9CE60435A11770000000000000000000000000000000000000000000000000000000000000000000000000000000000000014779877A7B0D9E8603169DDBD7836E478B462478900000000000000000000000000000000000000000000000000000000000000000000000000000000000000044C494E4B00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000F436861696E4C696E6B20546F6B656E00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014D1B482D1B947A96E96C9B76D15DE34F7F70A20A1000000000000000000000000").unwrap()).unwrap();

        dbg!(serde_json::to_string(&json).unwrap());

        assert_eq!(json, json!("zkgm"));
    }
}
