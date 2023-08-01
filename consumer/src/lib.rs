#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_crate_dependencies)]

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub use pallet::*;

#[frame_support::pallet(dev_mode)]
pub mod pallet {
    use sp_std::vec::Vec;
    use frame_support::{dispatch::DispatchResultWithPostInfo, pallet_prelude::*, PalletId, transactional};
    use frame_support::dispatch::DispatchErrorWithPostInfo;
    use frame_support::sp_runtime::{SaturatedConversion, traits::AccountIdConversion};
    use sp_core::{H256, U256};
    use frame_support::traits::{Currency, ExistenceRequirement, LockableCurrency};
    use frame_system::pallet_prelude::*;
    use pallet_bridge::Message;

    pub type BalanceOf<T> =
    <<T as pallet_bridge::Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    const RESOURCE_ACCOUNT: PalletId = PalletId(*b"ResrcAcc");

    #[derive(RuntimeDebug, Clone, Eq, PartialEq, Encode, Decode, TypeInfo)]
    pub struct Payload<T: Config> {
        pub amount: BalanceOf<T>,
        pub receiver: T::AccountId,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_bridge::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Currency: LockableCurrency<Self::AccountId, Moment = Self::BlockNumber>;
        #[pallet::constant]
        type AnchorAddress: Get<H256>;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::event]
    pub enum Event<T: Config> {}

    #[pallet::error]
    pub enum Error<T> {
        BalanceConvertFailed,
        AccountConvertFailed,
        InvalidPayloadLength,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(0)]
        #[transactional]
        pub fn send_message(
            origin: OriginFor<T>,
            amount: BalanceOf<T>,
            fee: BalanceOf<T>,
            dst_chain: u32,
            mut receiver: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            let sender = ensure_signed(origin)?;
            <T as pallet_bridge::Config>::Currency::transfer(
                &sender,
                &Self::resource_account(),
                amount,
                ExistenceRequirement::AllowDeath,
            )?;
            let mut fixed_amount= [0u8; 32];
            U256::from(amount.saturated_into::<u128>()).to_big_endian(&mut fixed_amount);
            let mut payload = fixed_amount.to_vec();
            payload.append(&mut receiver);
            let src_anchor = T::AnchorAddress::get();
            pallet_bridge::Pallet::<T>::send_message(
                sender,
                fee,
                src_anchor,
                dst_chain,
                payload,
            )
        }
    }

    impl<T: Config> Pallet<T> {
        pub(crate) fn resource_account() -> T::AccountId {
            RESOURCE_ACCOUNT.into_account_truncating()
        }

        fn parse_payload(raw: &[u8]) -> Result<Payload<T>, DispatchErrorWithPostInfo> {
            return if raw.len() >= 96 {
                let amount: u128 = U256::from_big_endian(&raw[..32])
                    .try_into()
                    .map_err(|_| Error::<T>::BalanceConvertFailed)?;
                // account id decode may different, ie. 'AccountId20', 'AccountId32', ..
                let account_len = T::AccountId::max_encoded_len();
                if account_len >= raw.len() {
                    return Err(Error::<T>::AccountConvertFailed.into())
                }
                let receiver = T::AccountId::decode(&mut raw[raw.len() - account_len..].as_ref())
                    .map_err(|_| Error::<T>::AccountConvertFailed)?;
                Ok(
                    Payload {
                        amount: SaturatedConversion::saturated_from(amount),
                        receiver,
                    }
                )
            } else {
                Err(Error::<T>::InvalidPayloadLength.into())
            }
        }
    }

    impl<T: Config> pallet_bridge::ConsumerLayer<T> for Pallet<T> {
        fn receive_op(message: &Message) -> DispatchResultWithPostInfo {
            let payload = Self::parse_payload(&message.payload)?;
            <T as pallet_bridge::Config>::Currency::transfer(
                &Self::resource_account(),
                &payload.receiver,
                payload.amount,
                ExistenceRequirement::AllowDeath,
            )?;
            Ok(().into())
        }

        fn anchor_addr() -> H256 {
            T::AnchorAddress::get()
        }
    }
}