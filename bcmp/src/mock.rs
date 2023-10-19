use std::marker::PhantomData;
use frame_support::dispatch::{DispatchResultWithPostInfo, Pays, PostDispatchInfo};
use crate as pallet_bcmp;
use frame_support::parameter_types;
use frame_support::sp_runtime::MultiSignature;
use frame_support::sp_runtime::traits::{IdentifyAccount, Verify};
use frame_support::traits::ConstU32;
use frame_system as system;
use sp_core::crypto::AccountId32;
use sp_core::H256;
use sp_runtime::{DispatchError, DispatchErrorWithPostInfo, testing::Header, traits::{BlakeTwo256, IdentityLookup}};
pub use pallet_bcmp::Event as bridge_event;
use crate::Message;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;
pub const SLOT_DURATION: u64 = 6000;
pub type Balance = u128;
pub const ALICE: AccountId = AccountId32::new([1u8; 32]);
pub const BOB: AccountId = AccountId32::new([2u8; 32]);
pub const CHARLIE: AccountId = AccountId32::new([3u8; 32]);
pub const DAVE: AccountId = AccountId32::new([4u8; 32]);
pub const EVE: AccountId = AccountId32::new([5u8; 32]);
pub const FALA: AccountId = AccountId32::new([6u8; 32]);
pub const DEFAULT_ADMIN_LIST: Option<AccountId32> = Some(CHARLIE);

pub type AccountId = <<MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;

frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
        Bcmp: pallet_bcmp::{Pallet, Call, Storage, Event<T>},
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const SS58Prefix: u8 = 42;
}

impl system::Config for Test {
    type BaseCallFilter = ();
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = BlockHashCount;
    type Version = ();
    type PalletInfo = PalletInfo;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = SS58Prefix;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

pub struct Consumer1<T> (PhantomData<T>);

impl crate::ConsumerLayer<Test> for Consumer1<Test> {
    fn receive_op(message: &Message) -> DispatchResultWithPostInfo {
        if message.extra_feed == vec![1, 1, 1] {
            return Err(DispatchErrorWithPostInfo {
                post_info: PostDispatchInfo {
                    actual_weight: None,
                    pays_fee: Pays::Yes,
                },
                error: DispatchError::Unavailable,
            });
        }
        Ok(().into())
    }

    fn anchor_addr() -> H256 {
        H256::zero()
    }
}

parameter_types! {
    pub const PureMessage: H256 = crate::pallet::PURE_MESSAGE;
    pub const DefaultAdmin: Option<AccountId> = DEFAULT_ADMIN_LIST;
}

impl pallet_bcmp::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type PureMessage = PureMessage;
    type DefaultAdmin = DefaultAdmin;
    type Consumers = Consumer1<Test>;
    type WeightInfo = pallet_bcmp::weight::BcmpWeight<Test>;
}

parameter_types! {
    pub const MaxLocks: u32 = 50;
    pub const ExistentialDeposit: u128 = 10;
}

impl pallet_balances::Config for Test {
    type MaxLocks = ConstU32<50>;
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    /// The type for recording an account's balance.
    type Balance = Balance;
    /// The ubiquitous event type.
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = pallet_balances::weights::SubstrateWeight<Test>;
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type HoldIdentifier = ();
    type MaxHolds = ();
}

parameter_types! {
    pub const MinimumPeriod: u64 = SLOT_DURATION / 2;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![
            (ALICE, 5000),
            (BOB, 5000),
            (CHARLIE, 5000),
            (DAVE, 5000),
            (EVE, 5000),
            (FALA, 5000),
        ],
    }.assimilate_storage(&mut t).unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| System::set_block_number(1));
    ext
}

pub(crate) fn last_event() -> RuntimeEvent {
    system::Pallet::<Test>::events()
        .pop()
        .expect("Event expected")
        .event
}

pub(crate) fn next_event() -> RuntimeEvent {
    let mut events = system::Pallet::<Test>::events();
    events.pop().expect("RuntimeEvent expected");
    events.pop()
        .expect("Next RuntimeEvent expected")
        .event
}

//compare "e" with last event
pub(crate) fn expect_event<E: Into<RuntimeEvent>>(e: E) {
    assert_eq!(last_event(), e.into());
}

pub(crate) fn expect_next_event<E: Into<RuntimeEvent>>(e: E) {
    assert_eq!(next_event(), e.into());
}
