#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_crate_dependencies)]
pub use pallet::*;

#[frame_support::pallet(dev_mode)]
pub mod pallet {
    use sp_std::vec::Vec;
    use frame_support::{dispatch::DispatchResultWithPostInfo, pallet_prelude::*};
    use sp_core::H256;
    use frame_support::traits::{Currency, LockableCurrency};
    use frame_system::pallet_prelude::*;
    use pallet_bridge::{CrossType, Message};

    pub type BalanceOf<T> =
    <<T as pallet_bridge::Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_bridge::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Currency: LockableCurrency<Self::AccountId, Moment = Self::BlockNumber>;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn new_tx_auth_list)]
    pub type NewTxAuthList<T: Config> = StorageValue<_, Vec<T::AccountId>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn cmt_channel_auth_list)]
    pub type CommitteeChannelAuthList<T: Config> = StorageValue<_, Vec<T::AccountId>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn auth_list_switch)]
    pub type HasAuthList<T: Config> = StorageValue<_, bool, ValueQuery>;

    #[pallet::event]
    pub enum Event<T: Config> {}

    #[pallet::error]
    pub enum Error<T> {}

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(0)]
        pub fn send_message(
            origin: OriginFor<T>,
            fee: BalanceOf<T>,
            cross_type: CrossType,
            src_anchor: H256,
            dst_chain: u32,
            extra_fee: Vec<u8>,
            payload: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            let sender = ensure_signed(origin)?;
            pallet_bridge::Pallet::<T>::send_message(
                sender,
                fee,
                cross_type,
                src_anchor,
                dst_chain,
                extra_fee,
                payload,
            )
        }
    }

    impl<T: Config> pallet_bridge::ConsumerInterface<T> for Pallet<T> {
        fn send_op(_message: &Message) -> DispatchResultWithPostInfo {
            Ok(().into())
        }

        fn receive_op(_message: &Message) -> DispatchResultWithPostInfo {
            Ok(().into())
        }
    }
}