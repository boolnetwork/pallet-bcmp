#![feature(tuple_trait)]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_crate_dependencies)]

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod fee;

pub use pallet::*;

#[frame_support::pallet(dev_mode)]
pub mod pallet {
    use sp_std::vec::Vec;
    use sp_std::vec;
    use sp_core::H256;
    use frame_support::{
        dispatch::DispatchResultWithPostInfo, pallet_prelude::*, PalletId, transactional,
    };
    use frame_support::sp_runtime::traits::AccountIdConversion;
    use frame_support::traits::{Currency, ExistenceRequirement, LockableCurrency};
    use frame_system::pallet_prelude::*;
    use scale_info::TypeInfo;
    use codec::{Decode, Encode};
    use crate::fee::GasConfig;
    use impl_trait_for_tuples::impl_for_tuples;

    pub type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    const FEE_COLLECTOR: PalletId = PalletId(*b"FCollect");

    #[derive(RuntimeDebug, Clone, PartialEq, Encode, Decode, TypeInfo)]
    pub struct Message {
        pub uid: H256,
        pub cross_type: H256,
        pub src_anchor: H256,
        pub extra_fee: Vec<u8>,
        pub dst_anchor: H256,
        pub payload: Vec<u8>,
    }

    #[derive(RuntimeDebug, Clone, PartialEq, Encode, Decode, TypeInfo)]
    pub struct AnchorInfo<AccountId> {
        pub admin: AccountId,
        pub cmt_pk: Vec<u8>,
        pub destinations: Vec<(u32, H256)>,
    }

    #[derive(RuntimeDebug, Clone, PartialEq, Encode, Decode, TypeInfo)]
    pub enum Role {
        /// supreme authority.
        Admin,
        /// Fee config authority.
        FeeController,
        /// Set global chain Id and register anchor.
        Operator,
        /// Claim rewards authority.
        Receiver,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Currency: LockableCurrency<Self::AccountId, Moment = Self::BlockNumber>;
        #[pallet::constant]
        type ThisChain: Get<u32>;
        #[pallet::constant]
        type PureMessage: Get<H256>;
        type Consumers: ConsumerLayer<Self>;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn get_global_chains)]
    pub type GlobalChainIds<T: Config> = StorageValue<_, Vec<u32>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn get_anchor_to_cmt_addr)]
    pub type AnchorAddrToInfo<T: Config> = StorageMap<_, Blake2_128Concat, H256, AnchorInfo<T::AccountId>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn get_chain_to_export_nonce)]
    pub type ChainToExportNonce<T: Config> = StorageMap<_, Blake2_128Concat, u32, u128, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn get_chain_to_import_uid)]
    pub type ChainToImportUid<T: Config> = StorageMap<_, Blake2_128Concat, u32, Vec<H256>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn get_whitelist)]
    pub type WhiteList<T: Config> = StorageMap<_, Blake2_128Concat, Role, Vec<T::AccountId>, ValueQuery, DefaultWhiteList<T>>;

    #[pallet::storage]
    #[pallet::getter(fn get_dst_chain_fee_standard)]
    pub type ChainToGasConfig<T: Config> = StorageMap<_, Blake2_128Concat, u32, GasConfig, ValueQuery>;

    #[pallet::type_value]
    pub fn DefaultWhiteList<T: Config>() -> Vec<T::AccountId> {
        vec![]
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        InitNewAnchor {
            creator: T::AccountId,
            anchor: H256,
        },
        MessageSent {
            message: Message,
        },
        MessageReceived {
            message: Message,
        }
    }

    #[pallet::error]
    pub enum Error<T> {
        AnchorAddressExist,
        AnchorAddressNotExist,
        InvalidDstChain,
        InvalidChainId,
        InvalidCommitteePubkey,
        InvalidCommitteeSignature,
        VerifyCommitteeSigFailed,
        MessageParseError,
        PathNotEnabled,
        PathAlreadyEnabled,
        NotAnchorAdmin,
        UnsupportedCrossType,
        AccountAlreadyInWhiteList,
        AccountNotAtWhiteList,
        UidAlreadyExist,
        ChainAlreadyExist,
        UnsupportedChainId,
        InsufficientFee,
        NeedAdmin,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(0)]
        #[transactional]
        pub fn set_whitelist_sudo(
            origin: OriginFor<T>,
            role: Role,
            account: T::AccountId,
        ) -> DispatchResultWithPostInfo {
            ensure_root(origin)?;
            let mut list = WhiteList::<T>::get(&role);
            ensure!(!list.contains(&account), Error::<T>::AccountAlreadyInWhiteList);
            list.push(account);
            WhiteList::<T>::insert(&role, list);
            Ok(().into())
        }

        #[pallet::weight(0)]
        #[transactional]
        pub fn set_whitelist(
            origin: OriginFor<T>,
            role: Role,
            account: T::AccountId,
        ) -> DispatchResultWithPostInfo {
            let sender = ensure_signed(origin)?;
            ensure!(WhiteList::<T>::get(&Role::Admin).contains(&sender), Error::<T>::NeedAdmin);
            let mut list = WhiteList::<T>::get(&role);
            ensure!(!list.contains(&account), Error::<T>::AccountAlreadyInWhiteList);
            list.push(account);
            WhiteList::<T>::insert(&role, list);
            Ok(().into())
        }

        #[pallet::weight(0)]
        #[transactional]
        pub fn set_chain_id(
            origin: OriginFor<T>,
            new_chain: u32,
        ) -> DispatchResultWithPostInfo {
            let sender = ensure_signed(origin)?;
            let this_chain = T::ThisChain::get();
            ensure!(this_chain != new_chain, Error::<T>::InvalidChainId);
            Self::role_check(Role::Admin, Role::Operator, &sender)?;
            ensure!(!GlobalChainIds::<T>::get().contains(&new_chain), Error::<T>::ChainAlreadyExist);
            GlobalChainIds::<T>::mutate(|old_chains| old_chains.push(new_chain));
            Ok(().into())
        }

        #[pallet::weight(0)]
        #[transactional]
        pub fn register_anchor(
            origin: OriginFor<T>,
            anchor: H256,
            cmt_pk: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            let creator = ensure_signed(origin)?;
            Self::role_check(Role::Admin, Role::Operator, &creator)?;
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
        #[transactional]
        pub fn enable_path(
            origin: OriginFor<T>,
            dst_chain_id: u32,
            dst_anchor: H256,
            anchor_addr: H256,
        ) -> DispatchResultWithPostInfo {
            let sender = ensure_signed(origin)?;
            ensure!(GlobalChainIds::<T>::get().contains(&dst_chain_id), Error::<T>::UnsupportedChainId);
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
        #[transactional]
        pub fn set_fee_config(
            origin: OriginFor<T>,
            new_config: GasConfig,
        ) -> DispatchResultWithPostInfo {
            let sender = ensure_signed(origin)?;
            Self::role_check(Role::Admin, Role::FeeController, &sender)?;
            ensure!(GlobalChainIds::<T>::get().contains(&new_config.chain_id), Error::<T>::UnsupportedChainId);
            ChainToGasConfig::<T>::mutate(&new_config.chain_id.clone(), |old_config|
                *old_config = new_config
            );
            Ok(().into())
        }

        #[pallet::weight(0)]
        #[transactional]
        pub fn claim_rewards(
            origin: OriginFor<T>,
            amount: BalanceOf<T>,
            to: T::AccountId,
        ) -> DispatchResultWithPostInfo {
            let sender = ensure_signed(origin)?;
            Self::role_check(Role::Admin, Role::Receiver, &sender)?;
            <T as Config>::Currency::transfer(
                &Self::fee_collector(),
                &to,
                amount,
                ExistenceRequirement::AllowDeath,
            )?;
            Ok(().into())
        }


        #[pallet::weight(0)]
        #[transactional]
        pub fn receive_message(
            origin: OriginFor<T>,
            cmt_sig: Vec<u8>,
            msg: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            ensure_signed(origin)?;
            let message = Message::decode(&mut msg.as_slice())
                .map_err(|_| Error::<T>::MessageParseError)?;
            let info = AnchorAddrToInfo::<T>::get(&message.dst_anchor)
                .ok_or(Error::<T>::AnchorAddressNotExist)?;
            // verify cmt sig
            Self::ed25519_verify(&info.cmt_pk, &msg, &cmt_sig)?;
            let (src_chain, dst_chain, _nonce) = Self::parse_uid(&message.uid);
            // check uid
            ensure!(
                !ChainToImportUid::<T>::get(&src_chain).contains(&message.uid),
                Error::<T>::UidAlreadyExist
            );
            // check src_chain
            ensure!(info.destinations.contains(&(src_chain, message.src_anchor)), Error::<T>::PathNotEnabled);
            ensure!(dst_chain == T::ThisChain::get(), Error::<T>::InvalidDstChain);
            ChainToImportUid::<T>::mutate(&src_chain, |value| value.push(message.uid));
            Self::deposit_event(Event::MessageReceived { message: message.clone() });
            T::Consumers::match_consumer(&message.dst_anchor, &message)?;
            Ok(().into())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn send_message(
            sender: T::AccountId,
            fee: BalanceOf<T>,
            src_anchor: H256,
            dst_chain: u32,
            payload: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            let info = AnchorAddrToInfo::<T>::get(&src_anchor)
                .ok_or(Error::<T>::AnchorAddressNotExist)?;
            let (_, dst_anchor) = info.destinations
                .iter()
                .find(|(chain_id, _dst_anchor)| chain_id == &dst_chain)
                .ok_or(Error::<T>::PathNotEnabled)?;
            // generate uid
            let this_chain = T::ThisChain::get();
            let uid = Self::compose_uid(
                this_chain,
                dst_chain,
                ChainToExportNonce::<T>::get(&dst_chain)
            );
            let resource_acc = Self::fee_collector();
            let fee_standard = ChainToGasConfig::<T>::get(&dst_chain);
            let total_fee = Self::calculate_total_fee(
                payload.len() as u64,
                fee_standard,
            );
            ensure!(total_fee <= fee, Error::<T>::InsufficientFee);

            <T as Config>::Currency::transfer(
                &sender,
                &resource_acc,
                fee,
                ExistenceRequirement::AllowDeath,
            )?;

            let message = Message {
                uid,
                cross_type: T::PureMessage::get(),
                src_anchor,
                extra_fee: Default::default(),
                dst_anchor: dst_anchor.clone(),
                payload
            };
            ChainToExportNonce::<T>::mutate(&dst_chain, |nonce| *nonce += 1);
            Self::deposit_event(Event::MessageSent { message: message.clone() });
            Ok(().into())
        }

        /// Compose uid from 'source_chain_id', 'dst_chain_id', 'nonce'
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

        /// Parse src_chain_id, dst_chain_id and nonce from uid
        fn parse_uid(uid: &H256) -> (u32, u32, u128) {
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

        pub(crate) fn fee_collector() -> T::AccountId {
            FEE_COLLECTOR.into_account_truncating()
        }

        pub(crate) fn role_check(role1: Role, role2: Role, sender: &T::AccountId) -> DispatchResultWithPostInfo {
            ensure!(
                WhiteList::<T>::get(&role1).contains(&sender) | WhiteList::<T>::get(&role2).contains(&sender),
                Error::<T>::AccountNotAtWhiteList
            );
            Ok(().into())
        }
    }

    pub trait ConsumerLayer<T: Config> {
        fn receive_op(
            message: &Message,
        ) -> DispatchResultWithPostInfo;

        fn anchor_addr() -> H256;

        fn match_consumer(anchor: &H256, message: &Message) -> DispatchResultWithPostInfo {
            if &Self::anchor_addr() == anchor {
                return Self::receive_op(message);
            }
            Ok(().into())
        }
    }

    #[impl_for_tuples(1, 5)]
    impl<T: Config> ConsumerLayer<T> for Tuple {
        fn receive_op(message: &Message) -> DispatchResultWithPostInfo {
            Ok(().into())
        }

        fn anchor_addr() -> H256 {
            H256::zero()
        }

        fn match_consumer(anchor: &H256, message: &Message) -> DispatchResultWithPostInfo {
            for_tuples!( #( Tuple::match_consumer(anchor, message)?; )* );
            Ok(().into())
        }
    }

}