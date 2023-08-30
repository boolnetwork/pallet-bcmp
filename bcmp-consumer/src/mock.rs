use std::marker::PhantomData;
use frame_support::dispatch::DispatchResultWithPostInfo;
use crate as pallet_bcmp_consumer;
use frame_support::parameter_types;
use frame_support::sp_runtime::MultiSignature;
use frame_support::sp_runtime::traits::{IdentifyAccount, Verify};
use frame_system as system;
use sp_core::crypto::AccountId32;
use sp_core::H256;
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
};
use pallet_bcmp::Message;

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
        System: frame_system::{Module, Call, Config, Storage, Event<T>},
        Balances: pallet_balances::{Module, Call, Storage, Config<T>, Event<T>},
        Bcmp: pallet_bcmp::{Module, Call, Storage, Event<T>},
        BcmpConsumer: pallet_bcmp_consumer::{Module, Call, Storage, Event<T>},
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
    type Origin = Origin;
    type Call = Call;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = Event;
    type BlockHashCount = BlockHashCount;
    type Version = ();
    type PalletInfo = PalletInfo;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = SS58Prefix;
    type AccountData = pallet_balances::AccountData<Balance>;
}

pub struct Consumer1<T> (PhantomData<T>);
impl pallet_bcmp::ConsumerLayer<Test> for Consumer1<Test> {
    fn receive_op(_message: &Message) -> DispatchResultWithPostInfo {
        Ok(().into())
    }

    fn anchor_addr() -> H256 {
        println!("call pallet consumer1");
        H256{0: [125u8, 110, 34, 168, 219, 139, 100, 140, 226, 72, 191, 237, 236, 186, 67, 113, 237, 34, 73, 74, 11, 120, 210, 51, 152, 152, 96, 33, 185, 27, 201, 162] }
    }
}

parameter_types! {
    pub const PureMessage: H256 = pallet_bcmp::PURE_MESSAGE;
    pub const DefaultAdmin: Option<AccountId> = DEFAULT_ADMIN_LIST;
}

impl pallet_bcmp::Config for Test {
    type Event = Event;
    type Currency = Balances;
    type PureMessage = PureMessage;
    type DefaultAdmin = DefaultAdmin;
    type Consumers = (Consumer1<Test>, BcmpConsumer);
    type WeightInfo = pallet_bcmp::weight::BcmpWeight<Test>;
}

parameter_types! {
    pub const AnchorAddress: H256 = H256{0: [126u8, 110, 34, 168, 219, 139, 100, 140, 226, 72, 191, 237, 236, 186, 67, 113, 237, 34, 73, 74, 11, 120, 210, 51, 152, 152, 96, 33, 185, 27, 201, 162] };
}

impl pallet_bcmp_consumer::Config for Test {
    type Event = Event;
    type Currency = Balances;
    type AnchorAddress = AnchorAddress;
}


parameter_types! {
    pub const MaxLocks: u32 = 50;
    pub const ExistentialDeposit: u128 = 10;
}

impl pallet_balances::Config for Test {
    type MaxLocks = MaxLocks;
    type Balance = Balance;
    type Event = Event;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = pallet_balances::weights::SubstrateWeight<Test>;
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
