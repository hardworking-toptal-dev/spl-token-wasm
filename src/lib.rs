mod wasm_signer;
mod wasm_signer_error;

use std::str::FromStr;
use solana_client_wasm::solana_sdk::pubkey::Pubkey;
use solana_client_wasm::solana_sdk::signature::Signer;
use wasm_bindgen::prelude::*;
use spl_token_2022::extension::{BaseStateWithExtensions, confidential_transfer, StateWithExtensionsOwned};
use spl_token_2022::extension::confidential_transfer::account_info::{ApplyPendingBalanceAccountInfo, TransferAccountInfo};
use spl_token_2022::extension::confidential_transfer::ConfidentialTransferAccount;
use spl_token_2022::proof::ProofLocation;
use spl_token_2022::solana_zk_token_sdk::encryption::auth_encryption::AeKey;
use spl_token_2022::solana_zk_token_sdk::encryption::elgamal::{ElGamalKeypair, ElGamalPubkey};
use spl_token_2022::solana_zk_token_sdk::instruction::TransferData;
use spl_token_2022::state::Account;
use web_sys::console;
use crate::wasm_signer::WasmSigner;

const DEFAULT_MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER: u64 = 65536;

#[wasm_bindgen]
pub async fn configure_confidential_transfer_instructions(
    // Simplified parameters for the example
    mint: String,
    token_account_address: String,
    owner_signer: WasmSigner,
) -> Result<JsValue, JsValue> {
    let mint_pubkey = Pubkey::from_str(&*mint).unwrap();
    let token_account_pubkey = Pubkey::from_str(&*token_account_address).unwrap();

    let elgamal_keypair = ElGamalKeypair::new_from_signer(&owner_signer, b"").unwrap();
    let aes_key = AeKey::new_from_signer(&owner_signer, b"").unwrap();

    let maximum_pending_balance_credit_counter = DEFAULT_MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER;

    let proof_data_temp =
        confidential_transfer::instruction::PubkeyValidityData::new(&elgamal_keypair).unwrap();
    let proof_location = ProofLocation::InstructionOffset(1.try_into().unwrap(), &proof_data_temp);

    let decryptable_balance = aes_key.encrypt(0);

    let ixes = &confidential_transfer::instruction::configure_account(
        &spl_token_2022::id(),
        &token_account_pubkey,
        &mint_pubkey,
        decryptable_balance,
        maximum_pending_balance_credit_counter,
        &owner_signer.pubkey(),
        &[],
        proof_location,
    ).unwrap();

    // Serialize instructions to pass back to JS
    let instructions_js = JsValue::from_serde(&ixes).map_err(|e| e.to_string())?;

    Ok(instructions_js)
}

#[wasm_bindgen]
pub async fn approve_account(
    mint: String,
    token_account_address: String,
    authority: String,
) -> Result<JsValue, JsValue> {
    let mint_pubkey = Pubkey::from_str(&*mint).unwrap();
    let token_account_pubkey = Pubkey::from_str(&*token_account_address).unwrap();
    let authority_pubkey = Pubkey::from_str(&*authority).unwrap();

    let ix = confidential_transfer::instruction::approve_account(
        &spl_token_2022::id(),
        &token_account_pubkey,
        &mint_pubkey,
        &authority_pubkey,
        &[],
    ).unwrap();

    let instruction_js = JsValue::from_serde(&ix).map_err(|e| e.to_string())?;

    Ok(instruction_js)
}

#[wasm_bindgen]
pub async fn deposit_confidential(
    mint: String,
    token_account_address: String,
    owner: String,
    amount: u64,
    decimals: u8,
) -> Result<JsValue, JsValue> {
    let mint_pubkey = Pubkey::from_str(&*mint).unwrap();
    let token_account_pubkey = Pubkey::from_str(&*token_account_address).unwrap();
    let owner_pubkey = Pubkey::from_str(&*owner).unwrap();

    let ix = confidential_transfer::instruction::deposit(
        &spl_token_2022::id(),
        &token_account_pubkey,
        &mint_pubkey,
        amount,
        decimals,
        &owner_pubkey,
        &[],
    ).unwrap();

    let instruction_js = JsValue::from_serde(&ix).map_err(|e| e.to_string())?;

    Ok(instruction_js)
}

#[wasm_bindgen]
pub async fn apply_pending(
    token_account_address: String,
    token_account_data: Vec<u8>,
    owner_signer: WasmSigner,
) -> Result<JsValue, JsValue> {
    let token_account_pubkey = Pubkey::from_str(&*token_account_address).unwrap();

    let owner_pubkey = owner_signer.pubkey();
    let owner_elgamal_keypair = ElGamalKeypair::new_from_signer(&owner_signer, b"").unwrap();
    let owner_aes_key = AeKey::new_from_signer(&owner_signer, b"").unwrap();

    let state_with_extension = StateWithExtensionsOwned::<Account>::unpack(token_account_data).unwrap();

    let extension_state = state_with_extension.get_extension::<ConfidentialTransferAccount>().unwrap();
    let account_info = ApplyPendingBalanceAccountInfo::new(extension_state);

    let expected_pending_balance_credit_counter = account_info.pending_balance_credit_counter();
    let new_decryptable_available_balance = account_info
        .new_decryptable_available_balance(owner_elgamal_keypair.secret(), &owner_aes_key)
        .unwrap();

    let ix = confidential_transfer::instruction::apply_pending_balance(
        &spl_token_2022::id(),
        &token_account_pubkey,
        expected_pending_balance_credit_counter,
        new_decryptable_available_balance,
        &owner_pubkey,
        &[],
    ).unwrap();

    let instruction_js = JsValue::from_serde(&ix).map_err(|e| e.to_string())?;

    Ok(instruction_js)
}

#[wasm_bindgen]
pub async fn transfer_confidential(
    mint: String,
    source_token_account_address: String,
    source_token_account_data: Vec<u8>,
    source_signer: WasmSigner,
    destination_token_account_address: String,
    destination_token_account_data: Vec<u8>,
    amount: u64,
) -> Result<JsValue, JsValue> {
    let mint_pubkey = Pubkey::from_str(&*mint).unwrap();
    let source_token_account_pubkey = Pubkey::from_str(&*source_token_account_address).unwrap();
    let owner_pubkey = source_signer.pubkey();
    let destination_token_account_pubkey = Pubkey::from_str(&*destination_token_account_address).unwrap();

    // let auditor_elgamal_pubkey = None;

    let sender_elgamal_keypair = ElGamalKeypair::new_from_signer(&source_signer, b"").unwrap();
    let sender_aes_key = AeKey::new_from_signer(&source_signer, b"").unwrap();

    let recipient_elgamal_pubkey: ElGamalPubkey =
        StateWithExtensionsOwned::<Account>::unpack(destination_token_account_data)
            .unwrap()
            .get_extension::<ConfidentialTransferAccount>()
            .unwrap()
            .elgamal_pubkey.try_into().unwrap();

    let source_account = StateWithExtensionsOwned::<Account>::unpack(source_token_account_data)
        .unwrap();
    let extension = source_account
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap();
    let transfer_account_info = TransferAccountInfo::new(extension);

    // let proof_data = transfer_account_info
    //     .generate_transfer_proof_data(
    //         amount,
    //         &sender_elgamal_keypair,
    //         &sender_aes_key,
    //         &recipient_elgamal_pubkey,
    //         auditor_elgamal_pubkey,
    //     ).unwrap();

    // For debugging
    let current_source_available_balance = transfer_account_info
        .available_balance
        .try_into().unwrap();
    let decryptable_available_balance = transfer_account_info
        .decryptable_available_balance
        .try_into().unwrap();
    let current_source_decrypted_available_balance = sender_aes_key
        .decrypt(&decryptable_available_balance).unwrap();

    let auditor_elgamal_pubkey_default = ElGamalPubkey::default();

    let proof_data = TransferData::new(
        amount,
        (
            current_source_decrypted_available_balance,
            &current_source_available_balance,
        ),
        &sender_elgamal_keypair,
        (&recipient_elgamal_pubkey, &auditor_elgamal_pubkey_default),
    ).unwrap();

    let proof_location = ProofLocation::InstructionOffset(1.try_into().unwrap(), &proof_data);

    let new_decryptable_available_balance = transfer_account_info
        .new_decryptable_available_balance(amount, &sender_aes_key).unwrap();

    let ixes = confidential_transfer::instruction::transfer(
        &spl_token_2022::id(),
        &source_token_account_pubkey,
        &mint_pubkey,
        &destination_token_account_pubkey,
        new_decryptable_available_balance,
        &owner_pubkey,
        &[],
        proof_location
    ).unwrap();

    console::log_2(&"data len:".into(), &ixes.get(1).unwrap().data.len().into());

    let instructions_js = JsValue::from_serde(&ixes).map_err(|e| e.to_string())?;

    Ok(instructions_js)
}