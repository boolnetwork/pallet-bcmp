use frame_support::RuntimeDebug;
use codec::{Encode, Decode};
use scale_info::TypeInfo;
use frame_support::sp_runtime::{Percent, SaturatedConversion};
use crate::{BalanceOf, Config};

#[derive(RuntimeDebug, Clone, PartialEq, Encode, Decode, Default, TypeInfo)]
pub struct GasConfig {
    // dst chain id.
    pub chain_id: u32,
    // Gas used for every byte of payload.
    pub gas_per_byte: u64,
    // Basic gas amount.
    pub base_gas_amount: u64,
    // GasPrice per gas(mist).
    pub gas_price: u64,
    // Exchange ratio is dst_price/src_price
    pub price_ratio: Percent,
    // Protocol fee ratio
    pub protocol_ratio: Percent
}

impl<T: Config> crate::Pallet<T> {
    pub(crate) fn calculate_total_fee(
        payload_size: u64,
        fee_standard: GasConfig,
    ) -> BalanceOf<T> {
        let relayer_fee =
            fee_standard.price_ratio * (((payload_size * fee_standard.gas_per_byte) + fee_standard.base_gas_amount) * fee_standard.gas_price);
        let protocol_fee = fee_standard.protocol_ratio * relayer_fee;
        SaturatedConversion::saturated_from(relayer_fee + protocol_fee)
    }
}
