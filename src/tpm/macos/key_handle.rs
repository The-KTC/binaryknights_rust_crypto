impl KeyHandle for TpmProvider {




    #[instrument]
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError>;{


    }

#[instrument]
fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError>; {

}



#[instrument]
fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError>; {
    

    if let Ok(string_data) = String::from_utf8(data.to_vec()) {
        let my_string = string_data;

        if unsafe {
            let encrypted_data = ffi::rustcall_encrypt_data(my_string, "3344".to_string()); 
            let my_bytes = encrypted_data.into_bytes();
            Ok(my_bytes)
        }
        .is_err()
        {
        return Err(SecurityModuleError::EncryptionError("Failed to encrypt the Data".to_string()));
        }

    } else {
        eprintln!("Data to string convertion error.");
    }
}
    


#[instrument]
fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError>;{

    if let Ok(string_data) = String::from_utf8(data.to_vec()) {
        if let Ok(string_signature) = String::from_utf8(signature.to_vec()) {

            let my_data = string_data;
            let my_signature = string_data;
    
            if unsafe {
                let data_verified_str = ffi::rustcall_verify_data(my_data, my_signature, "3344".to_string()); 
                
                // if (data_verified_str == true) { 
                //    Ok(true);
                // }
                // else {
                //    Ok(false);
                // }

                Ok(my_bytes)
            }
            .is_err()
            {
            return Err(SecurityModuleError::SignatureVerificationError("Failed to verify the signature".to_string()));
            }
    
        } else {
            eprintln!("Signature to string convertion error.");
        }

    } else {
        eprintln!("Data to string convertion error.");
    }

}


    #[swift_bridge::bridge]
    pub mod ffi{
        // Swift-Methods can be used in Rust 
        extern "Swift" {
            fn rustcall_create_key(privateKeyName: String) -> String;
            fn initializeModule() -> bool; 
            fn rustcall_load_key(keyID: String) -> String;
            fn rustcall_encrypt_data(data: String, publicKeyName: String) -> String; 
            fn rustcall_decrypt_data(data: String, privateKeyName: String) -> String; 
            fn rustcall_sign_data(data: String, privateKeyName: String) -> String;
            fn rustcall_verify_data(data: String, signature: String, publicKeyName: String) -> String; 
        }
    }
}
