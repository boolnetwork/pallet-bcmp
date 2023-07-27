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
    use sp_std::vec;
    use sp_core::H256;
    use frame_support::{dispatch::DispatchResultWithPostInfo, fail, pallet_prelude::*, PalletId};
    use frame_support::sp_runtime::traits::AccountIdConversion;
    use frame_support::traits::{Currency, ExistenceRequirement, LockableCurrency};
    use frame_system::pallet_prelude::*;

    pub type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    const BRIDGE_PALLET_ID: PalletId = PalletId(*b"Thismodl");

    #[derive(RuntimeDebug, Clone, PartialEq, Encode, Decode, TypeInfo)]
    pub struct MessageSent {
        pub uid: H256,
        pub cross_type: H256,
        pub src_anchor: H256,
        pub extra_fee: Vec<u8>,
        pub dst_anchor: H256,
        pub payload: Vec<u8>,
    }

    #[derive(RuntimeDebug, Clone, PartialEq, Encode, Decode, TypeInfo)]
    pub struct MessageReceived {
        pub uid: H256,
        pub cross_type: H256,
        pub src_anchor: H256,
        pub dst_anchor: H256,
    }

    #[derive(RuntimeDebug, Clone, PartialEq, Encode, Decode, TypeInfo)]
    pub enum CrossType {
        PureMessage,
        ValueMessage
    }

    #[derive(RuntimeDebug, Clone, PartialEq, Encode, Decode, TypeInfo)]
    pub struct AnchorInfo<AccountId> {
        pub admin: AccountId,
        pub cmt_pk: Vec<u8>,
        pub destinations: Vec<(u32, H256)>,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Currency: LockableCurrency<Self::AccountId, Moment = Self::BlockNumber>;
        type RuntimeCall: From<Call<Self>>;
        #[pallet::constant]
        type ThisChain: Get<u32>;
        #[pallet::constant]
        type PureMessage: Get<H256>;
        #[pallet::constant]
        type ValueMessage: Get<H256>;
        type ConsumerInterface: ConsumerInterface<Self>;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn fetch_anchor_to_cmt_addr)]
    pub type AnchorAddrToInfo<T: Config> = StorageMap<_, Blake2_128Concat, H256, AnchorInfo<T::AccountId>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn fetch_chain_to_none)]
    pub type DstChainToNonce<T: Config> = StorageMap<_, Blake2_128Concat, u32, u128, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        InitNewAnchor {
            creator: T::AccountId,
            anchor: H256,
        },
        MessageSent {
            message: MessageSent,
        },
        MessageReceived {
            message: MessageReceived,
        }
    }

    #[pallet::error]
    pub enum Error<T> {
        AnchorAddressExist,
        AnchorAddressNotExist,
        InvalidDstChain,
        CrossSelf,
        InvalidCommitteePubkey,
        InvalidCommitteeSignature,
        VerifyCommitteeSigFailed,
        MessageParseError,
        PathNotEnabled,
        PathAlreadyEnabled,
        NotAnchorAdmin,
        InvalidExtraFeed,
        UnsupportedCrossType,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(0)]
        pub fn register_anchor(
            origin: OriginFor<T>,
            cmt_pk: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            let creator = ensure_signed(origin)?;
            let anchor: H256 = sp_io::hashing::sha2_256(&cmt_pk).into();
            ensure!(!AnchorAddrToInfo::<T>::contains_key(&anchor), Error::<T>::AnchorAddressExist);
            let info = AnchorInfo {
                admin: creator.clone(),
                cmt_pk,
                destinations: vec![]
            };
            AnchorAddrToInfo::<T>::insert(&anchor, info);
            Self::deposit_event(Event::InitNewAnchor { creator, anchor });
            Ok(().into())
        }

        #[pallet::weight(0)]
        pub fn enable_path(
            origin: OriginFor<T>,
            dst_chain_id: u32,
            dst_anchor: H256,
            anchor_addr: H256,
        ) -> DispatchResultWithPostInfo {
            let sender = ensure_signed(origin)?;
            let mut info = AnchorAddrToInfo::<T>::get(&anchor_addr)
                .ok_or(Error::<T>::AnchorAddressNotExist)?;
            ensure!(info.admin == sender, Error::<T>::NotAnchorAdmin);
            ensure!(
                info.destinations.iter().find(|(chain_id, _)| chain_id == &dst_chain_id).is_none(),
                Error::<T>::PathAlreadyEnabled
            );
            info.destinations.push((dst_chain_id, dst_anchor));
            AnchorAddrToInfo::<T>::mutate(&anchor_addr, |pre_info| *pre_info = Some(info));
            Ok(().into())
        }

        #[pallet::weight(0)]
        pub fn receive_message(
            origin: OriginFor<T>,
            cmt_sig: Vec<u8>,
            msg: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            ensure_signed(origin)?;
            let message = MessageSent::decode(&mut msg.as_slice())
                .map_err(|_| Error::<T>::MessageParseError)?;
            let info = AnchorAddrToInfo::<T>::get(&message.dst_anchor)
                .ok_or(Error::<T>::AnchorAddressNotExist)?;
            // verify cmt sig
            Self::ed25519_verify(&info.cmt_pk, &msg, &cmt_sig)?;
            // check src_chain
            let (src_chain, dst_chain, _nonce) = Self::parse_uid(message.uid);
            ensure!(info.destinations.contains(&(src_chain, message.src_anchor)), Error::<T>::PathNotEnabled);
            ensure!(dst_chain == T::ThisChain::get(), Error::<T>::InvalidDstChain);
            let message = MessageReceived {
                uid: message.uid,
                cross_type: message.cross_type,
                src_anchor: message.src_anchor,
                dst_anchor: message.dst_anchor,
            };
            Self::deposit_event(Event::MessageReceived { message: message.clone() });
            T::ConsumerInterface::receive_op(&message)?;
            Ok(().into())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn send_message(
            sender: T::AccountId,
            fee: BalanceOf<T>,
            cross_type: CrossType,
            src_anchor: H256,
            dst_chain: u32,
            extra_fee: Vec<u8>,
            payload: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            Self::check_cross_type(&cross_type, &extra_fee)?;
            let this_chain = T::ThisChain::get();
            ensure!(this_chain != dst_chain, Error::<T>::CrossSelf);
            let info = AnchorAddrToInfo::<T>::get(&src_anchor)
                .ok_or(Error::<T>::AnchorAddressNotExist)?;
            let (_, dst_anchor) = info.destinations
                .iter()
                .find(|(chain_id, _dst_anchor)| chain_id == &dst_chain)
                .ok_or(Error::<T>::PathNotEnabled)?;
            // generate uid
            let uid = Self::compose_uid(this_chain, dst_chain, DstChainToNonce::<T>::get(&dst_chain));
            let resource_acc = Self::account_id();
            // todo: collect fee before handle message
            if let Err(e) = <T as Config>::Currency::transfer(
                &sender,
                &resource_acc,
                fee,
                ExistenceRequirement::AllowDeath,
            ) {
                fail!(e)
            }
            let message = MessageSent {
                uid,
                cross_type: Self::cross_type_into_h256(cross_type),
                src_anchor,
                extra_fee,
                dst_anchor: dst_anchor.clone(),
                payload
            };
            DstChainToNonce::<T>::mutate(&dst_chain, |nonce| *nonce += 1);
            Self::deposit_event(Event::MessageSent { message: message.clone() });
            T::ConsumerInterface::send_op(&message)?;
            Ok(().into())
        }

        fn compose_uid(
            src_chain: u32,
            dst_chain: u32,
            index: u128,
        ) -> H256 {
            let mut uid = [0u8; 32];
            uid[..4].copy_from_slice(&src_chain.to_be_bytes());
            uid[4..8].copy_from_slice(&dst_chain.to_be_bytes());
            uid[16..].copy_from_slice(&index.to_be_bytes());
            H256::from(uid)
        }

        // parse src_chain_id, dst_chain_id and nonce from uid
        fn parse_uid(uid: H256) -> (u32, u32, u128) {
            let mut src_chain_bytes = [0u8; 4];
            src_chain_bytes.copy_from_slice(&uid.0[..4]);
            let mut dst_chain_bytes = [0u8; 4];
            dst_chain_bytes.copy_from_slice(&uid.0[4..8]);
            let mut nonce_bytes = [0u8; 16];
            nonce_bytes.copy_from_slice(&uid.0[16..]);
            let src_chain = u32::from_be_bytes(src_chain_bytes);
            let dst_chain = u32::from_be_bytes(dst_chain_bytes);
            let nonce = u128::from_be_bytes(nonce_bytes);
            (src_chain, dst_chain, nonce)
        }

        pub fn check_cross_type(cross_type: &CrossType, extra_feed: &[u8]) -> DispatchResultWithPostInfo {
            match cross_type {
                CrossType::PureMessage => if extra_feed.len() != 0 {
                    return Err(Error::<T>::InvalidExtraFeed.into())
                },
                CrossType::ValueMessage => if extra_feed.len() < 96 {
                    return Err(Error::<T>::InvalidExtraFeed.into())
                }
            }
            Ok(().into())
        }

        /// Verify ed25519 signature
        pub fn ed25519_verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> DispatchResultWithPostInfo {
            use sp_core::ed25519::{Public, Signature};
            let pk = Public::try_from(pubkey).map_err(|_| Error::<T>::InvalidCommitteePubkey)?;
            let signature = Signature::try_from(sig).map_err(|_| Error::<T>::InvalidCommitteeSignature)?;
            if sp_io::crypto::ed25519_verify(&signature, msg, &pk) {
                Ok(().into())
            } else {
                Err(Error::<T>::VerifyCommitteeSigFailed.into())
            }
        }

        fn cross_type_into_h256(cross_type: CrossType) -> H256 {
            match cross_type {
                CrossType::PureMessage => T::PureMessage::get(),
                CrossType::ValueMessage => T::ValueMessage::get(),
            }
        }

        fn account_id() -> T::AccountId {
            BRIDGE_PALLET_ID.into_account_truncating()
        }
    }

    pub trait ConsumerInterface<T: Config> {
        fn send_op(
            message: &MessageSent,
        ) -> DispatchResultWithPostInfo;

        fn receive_op(
            message: &MessageReceived,
        ) -> DispatchResultWithPostInfo;
    }

}