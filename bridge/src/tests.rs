use std::str::FromStr;
use frame_support::{assert_noop, assert_ok};
use crate::{AnchorAddrToInfo, AnchorInfo, CrossType, DstChainToNonce, Error, MessageReceived, MessageSent};
use crate::mock::*;
use sp_core::{H256, Pair};
use codec::Encode;

#[test]
fn test_register_anchor() {
    new_test_ext().execute_with(|| {
        assert_ok!(Bridge::register_anchor(RuntimeOrigin::signed(ALICE), vec![1, 2, 3]));
        let hash: H256 = sp_io::hashing::sha2_256(&[1, 2, 3]).into();
        expect_event(bridge_event::InitNewAnchor {
            creator: ALICE,
            anchor: hash
        });
        assert_noop!(
            Bridge::register_anchor(RuntimeOrigin::signed(ALICE), vec![1, 2, 3]),
            Error::<Test>::AnchorAddressExist
        );
        let expect_info = AnchorInfo {
            admin: ALICE,
            cmt_pk: vec![1, 2, 3],
            destinations: vec![]
        };
        assert_eq!(AnchorAddrToInfo::<Test>::get(&hash) == Some(expect_info), true);
    })
}

#[test]
fn test_enable_path() {
    new_test_ext().execute_with(|| {
        assert_ok!(Bridge::register_anchor(RuntimeOrigin::signed(ALICE), vec![1, 2, 3]));
        let anchor_addr: H256 = sp_io::hashing::sha2_256(&[1, 2, 3]).into();
        let dst_anchor = H256::random();
        assert_noop!(
            Bridge::enable_path(RuntimeOrigin::signed(BOB), 31337, dst_anchor, anchor_addr),
            Error::<Test>::NotAnchorAdmin
        );
        assert_ok!(Bridge::enable_path(RuntimeOrigin::signed(ALICE), 31337, dst_anchor, anchor_addr));
        assert_noop!(
            Bridge::enable_path(RuntimeOrigin::signed(ALICE), 31337, dst_anchor, anchor_addr),
            Error::<Test>::PathAlreadyEnabled
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
fn test_send_message() {
    new_test_ext().execute_with(|| {
        let src_anchor: H256 = sp_io::hashing::sha2_256(&[1, 2, 3]).into();
        assert_noop!(
            Bridge::send_message(
                ALICE,
                100,
                CrossType::PureMessage,
                src_anchor,
                31338,
                vec![1],
                vec![],
            ),
            Error::<Test>::InvalidExtraFeed
        );
        assert_noop!(
            Bridge::send_message(
                ALICE,
                100,
                CrossType::PureMessage,
                src_anchor,
                31338,
                vec![],
                vec![],
            ),
            Error::<Test>::CrossSelf
        );
        assert_noop!(
            Bridge::send_message(
                ALICE,
                100,
                CrossType::PureMessage,
                src_anchor,
                31337,
                vec![],
                vec![],
            ),
            Error::<Test>::AnchorAddressNotExist
        );
        assert_ok!(Bridge::register_anchor(RuntimeOrigin::signed(ALICE), vec![1, 2, 3]));
        assert_noop!(
            Bridge::send_message(
                ALICE,
                100,
                CrossType::PureMessage,
                src_anchor,
                31337,
                vec![],
                vec![],
            ),
            Error::<Test>::PathNotEnabled
        );
        let dst_anchor = H256::random();
        assert_ok!(Bridge::enable_path(RuntimeOrigin::signed(ALICE), 31337, dst_anchor, src_anchor));

        assert_ok!(Bridge::send_message(
            ALICE,
            100,
            CrossType::PureMessage,
            src_anchor,
            31337,
            vec![],
            vec![],
        ));
        let message = MessageSent {
            uid: H256::from_str("00007A6A00007A69000000000000000000000000000000000000000000000000").unwrap(),
            cross_type: <Test as crate::Config>::PureMessage::get(),
            src_anchor,
            extra_fee: vec![],
            dst_anchor,
            payload: vec![]
        };
        expect_event(bridge_event::MessageSent {
            message
        });
        assert_eq!(
            DstChainToNonce::<Test>::get(&31337) == 1,
            true
        );
    })
}

#[test]
fn test_receive_message() {
    new_test_ext().execute_with(|| {
        let cmt_pair = sp_core::ed25519::Pair::generate().0;
        let pk = cmt_pair.public().0.to_vec();
        let dst_anchor: H256 = sp_io::hashing::sha2_256(&pk).into();
        let src_anchor = H256::random();
        let message = MessageSent {
            uid: H256::from_str("00007A6900007A6A000000000000000000000000000000000000000000000000").unwrap(),
            cross_type: <Test as crate::Config>::PureMessage::get(),
            src_anchor,
            extra_fee: vec![],
            dst_anchor,
            payload: vec![]
        };
        assert_noop!(
            Bridge::receive_message(
                RuntimeOrigin::signed(ALICE),
                vec![],
                vec![],
            ),
            Error::<Test>::MessageParseError
        );
        assert_noop!(
            Bridge::receive_message(
                RuntimeOrigin::signed(ALICE),
                vec![],
                message.encode(),
            ),
            Error::<Test>::AnchorAddressNotExist
        );

        assert_ok!(Bridge::register_anchor(RuntimeOrigin::signed(ALICE), pk));

        assert_noop!(
            Bridge::receive_message(
                RuntimeOrigin::signed(ALICE),
                vec![],
                message.encode(),
            ),
            Error::<Test>::InvalidCommitteeSignature
        );

        assert_noop!(
            Bridge::receive_message(
                RuntimeOrigin::signed(ALICE),
                [1u8; 64].to_vec(),
                message.encode(),
            ),
            Error::<Test>::VerifyCommitteeSigFailed
        );

        let mock_sig = cmt_pair.sign(&message.encode()).0.to_vec();

        assert_noop!(
            Bridge::receive_message(
                RuntimeOrigin::signed(ALICE),
                mock_sig.clone(),
                message.encode(),
            ),
            Error::<Test>::PathNotEnabled
        );
        assert_ok!(Bridge::enable_path(RuntimeOrigin::signed(ALICE), 31337, src_anchor, dst_anchor));
        assert_ok!(Bridge::receive_message(RuntimeOrigin::signed(ALICE), mock_sig, message.encode()));

        let message = MessageReceived {
            uid: message.uid,
            cross_type: message.cross_type,
            src_anchor: message.src_anchor,
            dst_anchor: message.dst_anchor,
        };
        expect_event(bridge_event::MessageReceived {
            message
        });
    })
}