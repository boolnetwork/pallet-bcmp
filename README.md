## Pallet-Bcmp

Base layer pallet which implement base features such as emitting `MessageSent` event and verifying committee's signature.

`Pallet-Bcmp` must **No Re-Creation** or it will cause to **LOST ASSET**.

## Pallet-Bcmp-Consumer

Consumer pallet depends on pallet-bcmp and supports custom features.

## Steps to use Bcmp:
### 1. Write custom consumer pallet. ie: [consumer-template](./bcmp-consumer).
#### Note:
##### a. Consumer pallet must depend on `pallet-bcmp` to emit `MessageSent` event and other receive message logic.
##### b. Consumer pallet must implement `ConsumerLayer` trait define at `pallet-bcmp`.
##### c. `AnchorAddress` at config should set by constant to ensure same as address which was registered at `pallet-bcmp`.

### 2. Add `pallet-bcmp` and `pallet-bcmp-consumer` to Runtime:
```rust
parameter_types! {
    pub const PureMessage: H256 = pallet_bcmp::PURE_MESSAGE;
    pub const DefaultAdmin: Option<AccountId> = consts::DefaultAdmin;
}

impl pallet_bcmp::Config for Runtime {
    type RuntimeEvent = ******;
    type Currency = ******;
    type PureMessage = PureMessage;
    type DefaultAdmin = DefaultAdmin;
    // Consumers can instance for (Consumer1, Consumer2, ..)
    type Consumers = BcmpConsumer;
    type WeightInfo = pallet_bcmp::weight::BcmpWeight<Runtime>;
}

parameter_types! {
    pub const AnchorAddress: H256 = ******;
}

impl pallet_bcmp_consumer::Config for Runtime {
    type RuntimeEvent = ******;
    type Currency = ******;
    type AnchorAddress = AnchorAddress;
}
```
#### Note:
Bcmp's `PureMessage` must use `pallet_bcmp::PURE_MESSAGE` constant.

Bcmp's `DefaultAdmin` is supplied for `No-Sudo` chain, it will init `WhiteList` storage if the value is Some.

Bcmp's `Consumers` support instance by (Consumer1, Consumer2, ..), anyone in tuple should implement `ConsumerLayer` trait.

Consumer's `AnchorAddress` can generate by `keccak256(&b"PALLET_CONSUMER"))`.

### 3. Init pallet-bcmp:
*  Step1: Set whitelist by call `set_whitelist`.
 We support two ways to set whitelist: `Root` or `Role::Admin`. if you want to call by the latter, `DefaultAdmin` of pallet-bcmp should set with Some Value.
* * You can use `Role::Admin` account to set other authority account. 
*  Step2: Call `set_this_chain_id` with the Id represent this chain, ie `sha2_256("Bool-Local".as_bytes())[..4]` to u32(big-endian).
*  Step3: Call `set_chain_id` to support other chain.
* * It will be failed if you don't set support chain id when enable path for anchor later.
* * Step4(Optional): Call `set_fee_config` to manage targe chain's fee config, default config to calculate fee is return `0`.
* * Step5(Optional): Call `emergency_control` to control `send_message` and `receive_message` to pause handle processing logic, require `Root` or `Role::Admin`. 
### 4. Init pallet-bcmp-consumer:
*  Step1: Create target committee and waiting for committee's pubkey has been generated.
*  Step2: Call `register_anchor` at pallet-bcmp.
* * `anchor` is a constant at consumer's config.
* * `cmt_pk` was generated at Step1.
*  Step3: Call `enable_path` at pallet-bcmp to bind other chain's anchor and committee.

### 5. Send cross-tx from you chain to another chain:
* Call `send_message` at pallet-bcmp-consumer, it should call pallet-bcmp's `send_message` finally to emit `MessageSent` event.
* `fee` parameter can calculate at [bcmp-fee-config](./bcmp/src/fee.rs).

### 6. Receive message from another chain:
*  After deliverer call the `receive_message` at pallet-bcmp, it will call consumer pallet's `receive_op` at trait `ConsumerLayer` if dispatch `Message`'s element `dst_anchor` successfully.
