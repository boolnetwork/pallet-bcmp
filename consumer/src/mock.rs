use std::marker::PhantomData;
use frame_support::dispatch::DispatchResultWithPostInfo;
use crate as pallet_consumer;
use frame_support::parameter_types;
use frame_support::sp_runtime::MultiSignature;
use frame_support::sp_runtime::traits::{IdentifyAccount, Verify};
use frame_support::traits::ConstU32;
use frame_system as system;
use sp_core::crypto::AccountId32;
use sp_core::H256;
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
};
use pallet_bridge::Message;

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
pub type AccountId = <<MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;

frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
        Bridge: pallet_bridge::{Pallet, Call, Storage, Event<T>},
        Consumer: pallet_consumer::{Pallet, Call, Storage, Event<T>},
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
impl pallet_bridge::ConsumerLayer<Test> for Consumer1<Test> {
    fn receive_op(_message: &Message) -> DispatchResultWithPostInfo {
        Ok(().into())
    }

    fn anchor_addr() -> H256 {
        println!("call pallet consumer1");
        H256{0: [125u8, 110, 34, 168, 219, 139, 100, 140, 226, 72, 191, 237, 236, 186, 67, 113, 237, 34, 73, 74, 11, 120, 210, 51, 152, 152, 96, 33, 185, 27, 201, 162] }
    }
}

parameter_types! {
    pub const ThisChain: u32 = 31338;
    pub const PureMessage: H256 = H256{0: [150u8, 108, 99, 209, 73, 57, 236, 154, 206, 45, 199, 68, 245, 234, 151, 14, 28, 198, 242, 15, 18, 175, 239, 220, 223, 245, 142, 213, 211, 33, 99, 126] };
}

impl pallet_bridge::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type ThisChain = ThisChain;
    type PureMessage = PureMessage;
    type Consumers = (Consumer1<Test>, Consumer);
}

parameter_types! {
    pub const AnchorAddress: H256 = H256{0: [126u8, 110, 34, 168, 219, 139, 100, 140, 226, 72, 191, 237, 236, 186, 67, 113, 237, 34, 73, 74, 11, 120, 210, 51, 152, 152, 96, 33, 185, 27, 201, 162] };
}

impl pallet_consumer::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type AnchorAddress = AnchorAddress;
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
