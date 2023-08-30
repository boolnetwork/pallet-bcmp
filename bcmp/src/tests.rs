use std::str::FromStr;
use frame_support::{assert_noop, assert_ok};
use crate::{AnchorAddrToInfo, AnchorInfo, ChainToExportNonce, ChainToGasConfig, ChainToImportUid, Error, GlobalChainIds, IsPaused, Message, Role, WhiteList};
use crate::mock::*;
use sp_core::{H256, Pair};
use codec::Encode;
use sp_runtime::Percent;
use crate::fee::GasConfig;
use crate::pallet::ConsumerLayer;

#[test]
fn test_set_whitelist() {
    new_test_ext().execute_with(|| {
        assert_eq!(WhiteList::<Test>::get(Role::Admin).contains(&CHARLIE), true);
        // test sudo
        assert_ok!(Bcmp::set_whitelist(Origin::root(), Role::Admin, ALICE));
        assert_noop!(
            Bcmp::set_whitelist(Origin::root(), Role::Admin, ALICE),
            Error::<Test>::AccountAlreadyInWhiteList,
        );
        assert_eq!(WhiteList::<Test>::get(Role::Admin).contains(&ALICE), true);

        // test admin
        assert_ok!(Bcmp::set_whitelist(Origin::signed(ALICE), Role::Admin, BOB));
        assert_noop!(
            Bcmp::set_whitelist(Origin::signed(ALICE), Role::Admin, BOB),
            Error::<Test>::AccountAlreadyInWhiteList,
        );
        assert_eq!(WhiteList::<Test>::get(Role::Admin).contains(&BOB), true);
    })
}

#[test]
fn test_set_chain_id() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Bcmp::set_chain_id(Origin::signed(ALICE), 0),
            Error::<Test>::InvalidChainId,
        );
        assert_noop!(
            Bcmp::set_chain_id(Origin::signed(ALICE), 31337),
            Error::<Test>::AccountNotAtWhiteList,
        );
        assert_ok!(Bcmp::set_whitelist(Origin::root(), Role::Admin, ALICE));
        assert_ok!(Bcmp::set_chain_id(Origin::signed(ALICE), 31337));
        assert_eq!(GlobalChainIds::<Test>::get().contains(&31337), true);
        assert_noop!(
            Bcmp::set_chain_id(Origin::signed(ALICE), 31337),
            Error::<Test>::ChainAlreadyExist,
        );
    })
}

#[test]
fn test_register_anchor() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Bcmp::register_anchor(Origin::signed(ALICE), H256::zero(), vec![1, 2, 3]),
            Error::<Test>::AccountNotAtWhiteList,
        );
        assert_ok!(Bcmp::set_whitelist(Origin::root(), Role::Admin, ALICE));
        assert_ok!(Bcmp::register_anchor(Origin::signed(ALICE), H256::zero(), vec![1, 2, 3]));
        expect_event(bridge_event::InitNewAnchor {
            creator: ALICE,
            anchor: H256::zero()
        });
        assert_noop!(
            Bcmp::register_anchor(Origin::signed(ALICE), H256::zero(), vec![1, 2, 3]),
            Error::<Test>::AnchorAddressExist,
        );
        let expect_info = AnchorInfo {
            admin: ALICE,
            cmt_pk: vec![1, 2, 3],
            destinations: vec![]
        };
        assert_eq!(AnchorAddrToInfo::<Test>::get(&H256::zero()) == Some(expect_info), true);
    })
}

#[test]
fn test_enable_path() {
    new_test_ext().execute_with(|| {
        assert_ok!(Bcmp::set_whitelist(Origin::root(), Role::Admin, ALICE));
        let anchor_addr = H256::zero();
        assert_ok!(Bcmp::register_anchor(Origin::signed(ALICE), anchor_addr, vec![1, 2, 3]));
        let dst_anchor = H256::random();

        assert_noop!(
            Bcmp::enable_path(Origin::signed(BOB), 31337, dst_anchor, anchor_addr),
            Error::<Test>::UnsupportedChainId,
        );
        assert_ok!(Bcmp::set_chain_id(Origin::signed(ALICE), 31337));
        assert_noop!(
            Bcmp::enable_path(Origin::signed(BOB), 31337, dst_anchor, anchor_addr),
            Error::<Test>::NotAnchorAdmin,
        );
        assert_ok!(Bcmp::enable_path(Origin::signed(ALICE), 31337, dst_anchor, anchor_addr));
        assert_noop!(
            Bcmp::enable_path(Origin::signed(ALICE), 31337, dst_anchor, anchor_addr),
            Error::<Test>::PathAlreadyEnabled,
        );
        let expect_info = AnchorInfo {
            admin: ALICE,
            cmt_pk: vec![1, 2, 3],
            destinations: vec![(31337, dst_anchor)]
        };
        assert_eq!(AnchorAddrToInfo::<Test>::get(&anchor_addr) == Some(expect_info), true);
    })
}

#[test]
fn test_set_fee_config() {
    new_test_ext().execute_with(|| {
        let new_config = GasConfig {
            chain_id: 31337,
            gas_per_byte: 1,
            base_gas_amount: 1,
            gas_price: 1,
            price_ratio: Percent::from_percent(10),
            protocol_ratio: Percent::from_percent(20),
        };
        assert_noop!(
            Bcmp::set_fee_config(Origin::signed(ALICE), new_config.clone()),
            Error::<Test>::AccountNotAtWhiteList,
        );
        assert_ok!(Bcmp::set_whitelist(Origin::root(), Role::Admin, ALICE));
        assert_noop!(
            Bcmp::set_fee_config(Origin::signed(ALICE), new_config.clone()),
            Error::<Test>::UnsupportedChainId,
        );
        assert_ok!(Bcmp::set_chain_id(Origin::signed(ALICE), 31337));
        assert_ok!(Bcmp::set_fee_config(Origin::signed(ALICE), new_config));
        assert_eq!(ChainToGasConfig::<Test>::get(31337).price_ratio, Percent::from_percent(10));
    })
}

#[test]
fn test_send_message() {
    new_test_ext().execute_with(|| {
        let src_anchor: H256 = sp_io::hashing::sha2_256(&[1, 2, 3]).into();
        assert_noop!(
            Bcmp::send_message(
                ALICE,
                100,
                src_anchor,
                31337,
                vec![],
            ),
            Error::<Test>::AnchorAddressNotExist,
        );
        assert_ok!(Bcmp::set_whitelist(Origin::root(), Role::Admin, ALICE));
        assert_ok!(Bcmp::register_anchor(Origin::signed(ALICE), src_anchor, vec![1, 2, 3]));
        assert_noop!(
            Bcmp::send_message(
                ALICE,
                100,
                src_anchor,
                31337,
                vec![],
            ),
            Error::<Test>::PathNotEnabled,
        );
        let dst_anchor = H256::random();
        assert_ok!(Bcmp::set_chain_id(Origin::signed(ALICE), 31337));
        assert_ok!(Bcmp::enable_path(Origin::signed(ALICE), 31337, dst_anchor, src_anchor));

        assert_ok!(Bcmp::send_message(
            ALICE,
            100,
            src_anchor,
            31337,
            vec![],
        ));
        assert_eq!(Balances::free_balance(&Bcmp::fee_collector()), 100);
        let message = Message {
            uid: H256::from_str("0000000000007A69000000000000000000000000000000000000000000000000").unwrap(),
            cross_type: <Test as crate::Config>::PureMessage::get(),
            src_anchor,
            extra_feed: vec![],
            dst_anchor,
            payload: vec![]
        };
        expect_event(bridge_event::MessageSent {
            message
        });
        assert_eq!(
            ChainToExportNonce::<Test>::get(&31337) == 1,
            true
        );

        // test claim rewards
        assert_ok!(Bcmp::claim_rewards(Origin::signed(ALICE), 50, ALICE));
        // 5000 - 100 + 50
        assert_eq!(Balances::free_balance(&ALICE), 4950);
    })
}

#[test]
fn test_receive_message() {
    new_test_ext().execute_with(|| {
        let cmt_pair = sp_core::ed25519::Pair::generate().0;
        let pk = cmt_pair.public().0.to_vec();
        let dst_anchor: H256 = H256::zero();
        let src_anchor = H256::random();
        let message = Message {
            uid: H256::from_str("00007A6900000000000000000000000000000000000000000000000000000000").unwrap(),
            cross_type: <Test as crate::Config>::PureMessage::get(),
            src_anchor,
            extra_feed: vec![],
            dst_anchor,
            payload: vec![]
        };
        // test bcmp status
        assert_ok!(Bcmp::emergency_control(Origin::root(), true));
        assert_eq!(IsPaused::<Test>::get(), true);
        assert_noop!(
            Bcmp::receive_message(
                Origin::signed(ALICE),
                vec![],
                vec![],
            ),
            Error::<Test>::IsPaused,
        );

        assert_ok!(Bcmp::emergency_control(Origin::root(), false));
        assert_noop!(
            Bcmp::receive_message(
                Origin::signed(ALICE),
                vec![],
                vec![],
            ),
            Error::<Test>::MessageParseError,
        );
        assert_noop!(
            Bcmp::receive_message(
                Origin::signed(ALICE),
                vec![],
                message.encode(),
            ),
            Error::<Test>::AnchorAddressNotExist,
        );
        assert_ok!(Bcmp::set_whitelist(Origin::root(), Role::Admin, ALICE));
        assert_ok!(Bcmp::register_anchor(Origin::signed(ALICE), dst_anchor, pk.clone()));

        assert_noop!(
            Bcmp::receive_message(
                Origin::signed(ALICE),
                vec![],
                message.encode(),
            ),
            Error::<Test>::InvalidCommitteeSignature,
        );

        assert_noop!(
            Bcmp::receive_message(
                Origin::signed(ALICE),
                [1u8; 64].to_vec(),
                message.encode(),
            ),
            Error::<Test>::VerifyCommitteeSigFailed,
        );

        let mock_sig = cmt_pair.sign(&message.encode()).0.to_vec();

        assert_noop!(
            Bcmp::receive_message(
                Origin::signed(ALICE),
                mock_sig.clone(),
                message.encode(),
            ),
            Error::<Test>::PathNotEnabled,
        );
        assert_ok!(Bcmp::set_chain_id(Origin::signed(ALICE), 31337));
        assert_ok!(Bcmp::enable_path(Origin::signed(ALICE), 31337, src_anchor, dst_anchor));

        let mock_anchor = H256::random();
        assert_ok!(<Consumer1<Test>>::match_consumer(&mock_anchor,&message));

        // match bcmp-consumer pallet successfully
        assert_ok!(Bcmp::receive_message(Origin::signed(ALICE), mock_sig.clone(), message.encode()));
        expect_event(bridge_event::MessageReceived {
            message: message.clone()
        });
        assert_noop!(
            Bcmp::receive_message(
                Origin::signed(ALICE),
                mock_sig.clone(),
                message.encode(),
            ),
            Error::<Test>::UidAlreadyExist,
        );
        assert_eq!(
            ChainToImportUid::<Test>::get(31337).contains(&H256::from_str("00007A6900000000000000000000000000000000000000000000000000000000").unwrap()),
            true,
        )
    })
}

#[test]
fn test_fee_calculate() {
    new_test_ext().execute_with(|| {
        let payload = [1u8; 96].to_vec();
        let fee_standard = GasConfig {
            chain_id: 31337,
            gas_per_byte: 1,
            base_gas_amount: 1,
            gas_price: 1,
            price_ratio: Percent::from_percent(10),
            protocol_ratio: Percent::from_percent(20),
        };
        let total_fee = Bcmp::calculate_total_fee(
            payload.len() as u64,
            fee_standard,
        );
        // relayer_fee: 10, protocol_fee: 2
        assert_eq!(total_fee, 10 + 2);
    })
}

#[test]
fn test_whitelist() {
    new_test_ext().execute_with(|| {
        assert_noop!(Bcmp::role_check(Role::Admin, Role::FeeController, &ALICE), Error::<Test>::AccountNotAtWhiteList);
        WhiteList::<Test>::mutate(Role::Admin, |list| list.push(ALICE));
        assert_ok!(Bcmp::role_check(Role::Admin, Role::FeeController, &ALICE));
        WhiteList::<Test>::mutate(Role::FeeController, |list| list.push(ALICE));
        assert_ok!(Bcmp::role_check(Role::Admin, Role::FeeController, &ALICE));
        WhiteList::<Test>::mutate(Role::FeeController, |list| list.push(BOB));
        assert_ok!(Bcmp::role_check(Role::Admin, Role::FeeController, &BOB));
    })
}
