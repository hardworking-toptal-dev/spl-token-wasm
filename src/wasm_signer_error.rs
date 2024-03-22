use wasm_bindgen::prelude::*;
use std::fmt;
use solana_client_wasm::solana_sdk::signature::SignerError;

// Define a wrapper error type that contains SignerError
pub struct WasmSignerError(SignerError);

impl fmt::Display for WasmSignerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Delegate to the inner SignerError's Display implementation
        write!(f, "{}", self.0)
    }
}

impl From<SignerError> for WasmSignerError {
    fn from(error: SignerError) -> Self {
        WasmSignerError(error)
    }
}

// Implement Into<JsValue> for WasmSignerError to satisfy wasm-bindgen's requirements
impl Into<JsValue> for WasmSignerError {
    fn into(self) -> JsValue {
        JsValue::from_str(&self.to_string())
    }
}
