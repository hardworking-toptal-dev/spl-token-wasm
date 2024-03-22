use wasm_bindgen::prelude::*;
use solana_client_wasm::{
    solana_sdk::signature::{Signature, SignerError},
};
use solana_client_wasm::solana_sdk::pubkey::Pubkey;
use solana_client_wasm::solana_sdk::signature::Signer;
use wasm_bindgen_futures::js_sys::Uint8Array;
use web_sys::console;

#[wasm_bindgen]
extern "C" {
    pub type JsSigner;

    #[wasm_bindgen(method, getter)]
    fn publicKey(this: &JsSigner) -> JsValue;

    #[wasm_bindgen(method)]
    fn signMessage(this: &JsSigner, message: Vec<u8>) -> JsValue;
}

// Helper function to convert JsValue to Pubkey
fn jsvalue_to_pubkey(value: JsValue) -> Result<Pubkey, SignerError> {
    console::log_2(&"Value:".into(), &value.clone().into());
    let uint8_array: Uint8Array = value.dyn_into().map_err(|_| SignerError::Custom("Expected Uint8Array for pubkey".to_string()))?;
    let bytes: Vec<u8> = uint8_array.to_vec();
    let p = Pubkey::try_from(bytes).map_err(|_| SignerError::Custom("Failed to create Pubkey".to_string()));

    console::log_2(&"Pubkey:".into(), &JsValue::from_str(p.as_ref().unwrap().to_string().as_str()));

    p
}

// Helper function to convert JsValue to Signature
fn jsvalue_to_signature(value: JsValue) -> Result<Signature, SignerError> {
    let uint8_array: Uint8Array = value.dyn_into().map_err(|_| SignerError::Custom("Expected Uint8Array for signature".to_string()))?;
    let bytes: Vec<u8> = uint8_array.to_vec();
    Signature::try_from(bytes).map_err(|_| SignerError::Custom("Signature conversion error".to_string()))
}

fn signature_to_js_value(signature: &Signature) -> JsValue {
    // Convert the signature to a byte array
    let bytes = signature.as_ref();
    // Use `JsValue::from_serde` to convert the byte array into `JsValue`
    JsValue::from_serde(&bytes).unwrap()
}

// A Rust struct that will hold a JavaScript signer object
#[wasm_bindgen]
pub struct WasmSigner {
    signer: JsSigner, // Holds the actual JavaScript signer object
}

#[wasm_bindgen]
impl WasmSigner {
    pub fn new(signer: JsSigner) -> WasmSigner {
        WasmSigner { signer }
    }
}

// Implement the Signer trait for WasmSigner
impl Signer for WasmSigner {
    fn pubkey(&self) -> Pubkey {
        self.try_pubkey().unwrap()
    }

    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        jsvalue_to_pubkey(self.signer.publicKey())
    }

    fn sign_message(&self, message: &[u8]) -> Signature {
        self.try_sign_message(message).unwrap()
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // let signer: &JsSigner = self.signer.dyn_ref().expect("Failed to cast JsValue to JsSigner");
        // let signature_js = signer.try_sign_message(message.to_vec()).map_err(|_| SignerError::Custom("JS signer try_sign_message failed".to_string()))?;

        let signature_js = self.signer.signMessage(message.to_vec());
        jsvalue_to_signature(signature_js)
    }

    fn is_interactive(&self) -> bool {
        true
    }
}
