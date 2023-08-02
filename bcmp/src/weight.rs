use sp_std::marker::PhantomData;
use frame_support::weights::Weight;

/// Weight functions needed for pallet_bcmp.
pub trait WeightInfo {
    fn set_whitelist() -> Weight;
    fn set_this_chain_id() -> Weight;
    fn set_chain_id() -> Weight;
    fn register_anchor() -> Weight;
    fn enable_path() -> Weight;
    fn set_fee_config() -> Weight;
    fn claim_rewards() -> Weight;
    fn receive_message() -> Weight;
    fn emergency_control() -> Weight;
}

pub struct BcmpWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for BcmpWeight<T> {
    fn set_whitelist() -> Weight {
        Weight::from_all(0u64)
    }

    fn set_this_chain_id() -> Weight {
        Weight::from_all(0u64)
    }

    fn set_chain_id() -> Weight {
        Weight::from_all(0u64)
    }

    fn register_anchor() -> Weight {
        Weight::from_all(0u64)
    }

    fn enable_path() -> Weight {
        Weight::from_all(0u64)
    }

    fn set_fee_config() -> Weight {
        Weight::from_all(0u64)
    }

    fn claim_rewards() -> Weight {
        Weight::from_all(0u64)
    }

    fn receive_message() -> Weight {
        Weight::from_all(0u64)
    }

    fn emergency_control() -> Weight {
        Weight::from_all(0u64)
    }
}