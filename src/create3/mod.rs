use alloy_primitives::{keccak256, U256};
use alloy_sol_types::SolValue;
use pgrx::pg_extern;

mod copy;

#[pg_extern(immutable, parallel_safe)]
pub fn create3_0_2(intermediate_channel_ids: &[u8], receiver_channel_id: i64, wrapped_token: &[u8], deployer: &[u8]) -> Vec<u8> {
    // TODO: be or le? + error handling
    let intermediate_channel_ids: U256 = U256::try_from_be_slice(intermediate_channel_ids).unwrap();
    let params = (intermediate_channel_ids, receiver_channel_id, wrapped_token);
    let encoded = params.abi_encode_params();
    let salt = keccak256(encoded);

    copy::predict_deterministic_address(deployer, &salt).into()
}

#[cfg(any(test, feature = "pg_test"))]
// #[pg_schema]
mod tests {
    use super::*;

    #[test]
    fn test_known_address() {
        // data for this test case obtain from  https://dashboard.tenderly.co/Kaiserkarel/project/simulator/56ee03c1-60ce-448b-a26d-c1736f9f2d9c?sharedSimulation=true
        let wrapped_token = hex::decode("779877A7B0D9E8603169DdbD7836e478b4624789").unwrap();
        let deployer = hex::decode("7b7872fec715c787a1be3f062adedc82b3b06144").unwrap();

        let unwrapped_token = create3_0_2(&[], 5, &wrapped_token, &deployer);

        let expected = hex::decode("d1b482d1b947a96e96c9b76d15de34f7f70a20a1").unwrap();
        assert_eq!(unwrapped_token, expected);
    }

    #[test]
    fn test_unknown_address() {
        // data for this test case obtain from  https://dashboard.tenderly.co/Kaiserkarel/project/simulator/56ee03c1-60ce-448b-a26d-c1736f9f2d9c?sharedSimulation=true
        let wrapped_token = hex::decode("dead77A7B0D9E8603169DdbD7836e478b4624789").unwrap();
        let deployer = hex::decode("7b7872fec715c787a1be3f062adedc82b3b06144").unwrap();

        let unwrapped_token = create3_0_2(&[], 5, &wrapped_token, &deployer);

        let expected = hex::decode("c8e644527dbab144963b61dfa6d26bde0ea5a30f").unwrap();
        assert_eq!(unwrapped_token, expected);
    }

    #[test]
    fn test_unknown_deployer() {
        // data for this test case obtain from  https://dashboard.tenderly.co/Kaiserkarel/project/simulator/56ee03c1-60ce-448b-a26d-c1736f9f2d9c?sharedSimulation=true
        let wrapped_token = hex::decode("779877A7B0D9E8603169DdbD7836e478b4624789").unwrap();
        let deployer = hex::decode("dead72fec715c787a1be3f062adedc82b3b06144").unwrap();

        let unwrapped_token = create3_0_2(&[], 5, &wrapped_token, &deployer);

        let expected = hex::decode("33e8243bd092906ddfaff01a6b1d77535e404b92").unwrap();
        assert_eq!(unwrapped_token, expected);
    }

    #[test]
    fn test_invalid_wrapped_token_length() {
        // data for this test case obtain from  https://dashboard.tenderly.co/Kaiserkarel/project/simulator/56ee03c1-60ce-448b-a26d-c1736f9f2d9c?sharedSimulation=true
        let wrapped_token = hex::decode("dead").unwrap();
        let deployer = hex::decode("7b7872fec715c787a1be3f062adedc82b3b06144").unwrap();

        let unwrapped_token = create3_0_2(&[], 5, &wrapped_token, &deployer);

        let expected = hex::decode("ff5602d75a72342f22da2eb288875b4e281c368d").unwrap();
        assert_eq!(unwrapped_token, expected);
    }

    #[test]
    fn test_invalid_deployer_length() {
        // data for this test case obtain from  https://dashboard.tenderly.co/Kaiserkarel/project/simulator/56ee03c1-60ce-448b-a26d-c1736f9f2d9c?sharedSimulation=true
        let wrapped_token = hex::decode("779877A7B0D9E8603169DdbD7836e478b4624789").unwrap();
        let deployer = hex::decode("dead").unwrap();

        let unwrapped_token = create3_0_2(&[], 5, &wrapped_token, &deployer);

        let expected = hex::decode("5d593a96203d28f570087c197213042cc842f410").unwrap();
        assert_eq!(unwrapped_token, expected);
    }

    #[test]
    fn test_zero_wrapped_token_length() {
        // data for this test case obtain from  https://dashboard.tenderly.co/Kaiserkarel/project/simulator/56ee03c1-60ce-448b-a26d-c1736f9f2d9c?sharedSimulation=true
        let wrapped_token = hex::decode("").unwrap();
        let deployer = hex::decode("7b7872fec715c787a1be3f062adedc82b3b06144").unwrap();

        let unwrapped_token = create3_0_2(&[], 5, &wrapped_token, &deployer);

        let expected = hex::decode("f18740a55a6b2692e9235978ef97270d2e06ac2f").unwrap();
        assert_eq!(unwrapped_token, expected);
    }

    #[test]
    fn test_zero_deployer_length() {
        // data for this test case obtain from  https://dashboard.tenderly.co/Kaiserkarel/project/simulator/56ee03c1-60ce-448b-a26d-c1736f9f2d9c?sharedSimulation=true
        let wrapped_token = hex::decode("779877A7B0D9E8603169DdbD7836e478b4624789").unwrap();
        let deployer = hex::decode("").unwrap();

        let unwrapped_token = create3_0_2(&[], 5, &wrapped_token, &deployer);

        let expected = hex::decode("041832cd16762bd5c81e971b3df9ba69d67bfbf7").unwrap();
        assert_eq!(unwrapped_token, expected);
    }
}