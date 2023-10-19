#![feature(tuple_trait)]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_crate_dependencies)]

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod fee;
pub mod weight;

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
    use crate::{fee::GasConfig, weight::WeightInfo};
    use impl_trait_for_tuples::impl_for_tuples;

    pub type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    /// Not allow change, get it from keccak256(&b"PURE_MESSAGE")): "0x966c63d14939ec9ace2dc744f5ea970e1cc6f20f12afefdcdff58ed5d321637e"
    pub const PURE_MESSAGE: H256 = H256{0: [150u8, 108, 99, 209, 73, 57, 236, 154, 206, 45, 199, 68, 245, 234, 151, 14, 28, 198, 242, 15, 18, 175, 239, 220, 223, 245, 142, 213, 211, 33, 99, 126] };

    const FEE_COLLECTOR: PalletId = PalletId(*b"FCollect");

    #[derive(RuntimeDebug, Clone, PartialEq, Encode, Decode, TypeInfo)]
    pub struct Message {
        /// UniqueIdentification, contains 'src_chain', 'dst_chain', 'none'.
        pub uid: H256,
        /// Only support 'Bcmp::Config::PureMessage' constant.
        pub cross_type: H256,
        /// Bind bcmp-consumer by 'BcmpConsumer::Config::AnchorAddress' constant.
        pub src_anchor: H256,
        /// Unsupported yet, Default value is empty Vector.
        pub extra_feed: Vec<u8>,
        /// Destination anchor address for target chain.
        pub dst_anchor: H256,
        /// Extra logic for bcmp-consumer.
        pub payload: Vec<u8>,
    }

    #[derive(RuntimeDebug, Clone, PartialEq, Encode, Decode, TypeInfo)]
    pub struct AnchorInfo<AccountId> {
        /// Anchor creator.
        pub admin: AccountId,
        /// Committee pubkey.
        pub cmt_pk: Vec<u8>,
        /// Bind chain_id with anchor_address.
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
        type PureMessage: Get<H256>;
        #[pallet::constant]
        type DefaultAdmin: Get<Option<Self::AccountId>>;
        /// Consumers can instance for (Consumer1, Consumer2, ..).
        type Consumers: ConsumerLayer<Self>;
        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Id represent this chain, ie 'sha2_256("Bool-Local".as_bytes())[..4]' to u32(big-endian).
    #[pallet::storage]
    #[pallet::getter(fn get_this_chain_id)]
    pub type ThisChainId<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Global chains which are supported to 'enable_path' and 'set_fee_config'.
    #[pallet::storage]
    #[pallet::getter(fn get_global_chains)]
    pub type GlobalChainIds<T: Config> = StorageValue<_, Vec<u32>, ValueQuery>;

    /// Mapping 'anchor_address' to anchor info.
    #[pallet::storage]
    #[pallet::getter(fn get_anchor_to_cmt_addr)]
    pub type AnchorAddrToInfo<T: Config> = StorageMap<_, Blake2_128Concat, H256, AnchorInfo<T::AccountId>, OptionQuery>;

    /// Mapping 'chain_id' to next nonce.
    #[pallet::storage]
    #[pallet::getter(fn get_chain_to_export_nonce)]
    pub type ChainToExportNonce<T: Config> = StorageMap<_, Blake2_128Concat, u32, u128, ValueQuery>;

    /// Mapping 'chain_id' to uid list.
    #[pallet::storage]
    #[pallet::getter(fn get_chain_to_import_uid)]
    pub type ChainToImportUid<T: Config> = StorageMap<_, Blake2_128Concat, u32, Vec<H256>, ValueQuery>;

    /// Mapping 'Role' to account list.
    #[pallet::storage]
    #[pallet::getter(fn get_whitelist)]
    pub type WhiteList<T: Config> = StorageMap<_, Blake2_128Concat, Role, Vec<T::AccountId>, ValueQuery, DefaultWhiteList<T>>;

    /// Mapping 'chain_id' to 'GasConfig'.
    #[pallet::storage]
    #[pallet::getter(fn get_dst_chain_fee_standard)]
    pub type ChainToGasConfig<T: Config> = StorageMap<_, Blake2_128Concat, u32, GasConfig, ValueQuery>;

    /// Control send and receive message, default value is 'false'.
    #[pallet::storage]
    #[pallet::getter(fn is_paused)]
    pub type IsPaused<T: Config> = StorageValue<_, bool, ValueQuery>;

    #[pallet::type_value]
    pub fn DefaultWhiteList<T: Config>() -> Vec<T::AccountId> {
        if let Some(account) = T::DefaultAdmin::get() {
            return vec![account];
        } else {
            vec![]
        }
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
        },
        MessageDeliverFailed {
            uid: H256,
            dst_anchor: H256,
            error: DispatchError,
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
        IsPaused,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Receive cross message from other chain.
        /// Called by off-chain deliverer.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::receive_message())]
        #[transactional]
        pub fn receive_message(
            origin: OriginFor<T>,
            cmt_sig: Vec<u8>,
            msg: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            ensure_signed(origin)?;
            ensure!(!IsPaused::<T>::get(), Error::<T>::IsPaused);
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
            ensure!(dst_chain == ThisChainId::<T>::get(), Error::<T>::InvalidDstChain);
            match T::Consumers::match_consumer(&message.dst_anchor, &message) {
                Ok(_) => ChainToImportUid::<T>::mutate(&src_chain, |value| value.push(message.uid)),
                Err(e) =>
                    Self::deposit_event(Event::MessageDeliverFailed {
                        uid: message.uid,
                        dst_anchor: message.dst_anchor,
                        error: e.error
                    }),
            };
            Self::deposit_event(Event::MessageReceived { message: message.clone() });
            Ok(().into())
        }

        /// Insert new account to target whitelist by 'Role::Admin' authority.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::set_whitelist())]
        #[transactional]
        pub fn set_whitelist(
            origin: OriginFor<T>,
            role: Role,
            account: T::AccountId,
        ) -> DispatchResultWithPostInfo {
            if ensure_root(origin.clone()).is_err() {
                let sender = ensure_signed(origin)?;
                ensure!(
                    WhiteList::<T>::get(&Role::Admin).contains(&sender),
                    Error::<T>::NeedAdmin,
                );
            }
            let mut list = WhiteList::<T>::get(&role);
            ensure!(!list.contains(&account), Error::<T>::AccountAlreadyInWhiteList);
            list.push(account);
            WhiteList::<T>::insert(&role, list);
            Ok(().into())
        }

        /// Set current chain id by 'Role::Admin' or 'Role::Operator' authority.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::set_this_chain_id())]
        #[transactional]
        pub fn set_this_chain_id(
            origin: OriginFor<T>,
            chain_id: u32,
        ) -> DispatchResultWithPostInfo {
            let sender = ensure_signed(origin)?;
            let this_chain = ThisChainId::<T>::get();
            ensure!(this_chain != chain_id, Error::<T>::InvalidChainId);
            Self::role_check(Role::Admin, Role::Operator, &sender)?;
            ThisChainId::<T>::mutate(|old_chain_id| *old_chain_id = chain_id);
            Ok(().into())
        }

        /// Set supported destination chain id by 'Role::Admin' or 'Role::Operator' authority.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::set_chain_id())]
        #[transactional]
        pub fn set_chain_id(
            origin: OriginFor<T>,
            new_chain: u32,
        ) -> DispatchResultWithPostInfo {
            let sender = ensure_signed(origin)?;
            let this_chain = ThisChainId::<T>::get();
            ensure!(this_chain != new_chain, Error::<T>::InvalidChainId);
            Self::role_check(Role::Admin, Role::Operator, &sender)?;
            ensure!(!GlobalChainIds::<T>::get().contains(&new_chain), Error::<T>::ChainAlreadyExist);
            GlobalChainIds::<T>::mutate(|old_chains| old_chains.push(new_chain));
            Ok(().into())
        }

        /// Register anchor address with committee pubkey, anchor should from consumer pallet constant.
        /// Must called by 'Role::Admin' or 'Role::Operator' authority.
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::register_anchor())]
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

        /// Extend destination chain id with anchor address.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::enable_path())]
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

        /// Set 'GasConfig' for target chain by 'Role::Admin' or 'Role::FeeController' authority.
        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::set_fee_config())]
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

        /// Transfer rewards from resource account to target account.
        /// Must called by 'Role::Admin' or 'Role::Receiver' authority.
        #[pallet::call_index(7)]
        #[pallet::weight(T::WeightInfo::claim_rewards())]
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

        /// Control bcmp to send and receive message.
        /// Require Root or Admin role.
        #[pallet::call_index(8)]
        #[pallet::weight(T::WeightInfo::emergency_control())]
        #[transactional]
        pub fn emergency_control(
            origin: OriginFor<T>,
            is_paused: bool,
        ) -> DispatchResultWithPostInfo {
            if ensure_root(origin.clone()).is_err() {
                let sender = ensure_signed(origin)?;
                ensure!(
                    WhiteList::<T>::get(&Role::Admin).contains(&sender),
                    Error::<T>::AccountNotAtWhiteList
                );
            }
            IsPaused::<T>::put(is_paused);
            Ok(().into())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Called by consumer pallet, source anchor must already be registered.
        pub fn send_message(
            sender: T::AccountId,
            fee: BalanceOf<T>,
            src_anchor: H256,
            dst_chain: u32,
            payload: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            ensure!(!IsPaused::<T>::get(), Error::<T>::IsPaused);
            let info = AnchorAddrToInfo::<T>::get(&src_anchor)
                .ok_or(Error::<T>::AnchorAddressNotExist)?;
            let (_, dst_anchor) = info.destinations
                .iter()
                .find(|(chain_id, _dst_anchor)| chain_id == &dst_chain)
                .ok_or(Error::<T>::PathNotEnabled)?;
            // generate uid
            let this_chain = ThisChainId::<T>::get();
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
                extra_feed: Default::default(),
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

        /// Resource account to collect cross fee.
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

    /// Every consumer pallet must implement this trait
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