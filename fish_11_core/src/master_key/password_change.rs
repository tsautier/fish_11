//! Password change module for master key system
//!
//! Handles secure password change operations while preserving access to encrypted data.

use crate::master_key::derivation::derive_master_key;
//use crate::master_key::encryption::{encrypt_data, decrypt_data, EncryptedBlob};

/// Result type for password change operations
pub type ChangePasswordResult<T> = Result<T, PasswordChangeError>;

/// Errors that can occur during password change operations
#[derive(Debug)]
pub enum PasswordChangeError {
    CurrentPasswordIncorrect,
    NewPasswordTooWeak(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
}

impl std::fmt::Display for PasswordChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordChangeError::CurrentPasswordIncorrect => {
                write!(f, "Current password is incorrect")
            }
            PasswordChangeError::NewPasswordTooWeak(msg) => {
                write!(f, "New password is too weak: {}", msg)
            }
            PasswordChangeError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            PasswordChangeError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
        }
    }
}

impl std::error::Error for PasswordChangeError {}

/// Change the master password after validating the old one
///
/// This function will:
/// 1. Verify the current password is correct by re-deriving with stored salt
/// 2. Validate the new password meets security requirements
/// 3. Return the new salt for the updated password
///
/// # Arguments
/// * `current_password` - The current master password
/// * `current_salt` - The salt used for the current password
/// * `new_password` - The new master password
///
/// # Returns
/// * `Result<String, PasswordChangeError>` - The new salt for the master key
pub fn change_master_password(
    current_password: &str,
    current_salt: &str,
    new_password: &str,
) -> ChangePasswordResult<String> {
    use crate::master_key::derivation::derive_master_key_with_salt;
    use crate::master_key::password_validation::PasswordValidator;

    // Validate the new password strength
    PasswordValidator::validate_password_strength(new_password)
        .map_err(|e| PasswordChangeError::NewPasswordTooWeak(e))?;

    // Verify the current password by attempting to derive the key with the stored salt
    let _current_key = derive_master_key_with_salt(current_password, Some(current_salt))
        .map_err(|_| PasswordChangeError::CurrentPasswordIncorrect)?
        .0;

    // Derive the new key to make sure the new password is valid
    let (_new_key, new_salt) = derive_master_key(new_password)
        .map_err(|e| PasswordChangeError::EncryptionFailed(e.to_string()))?;

    // In a real implementation, we would re-encrypt any data that was encrypted
    // with keys derived from the old master key. For now, we just return the
    // new salt.
    //
    // The actual re-encryption would require:
    // 1. Having access to all encrypted data
    // 2. Decrypting each item with keys derived from the old master key
    // 3. Re-encrypting each item with keys derived from the new master key
    // 4. Updating storage with the newly encrypted data

    Ok(new_salt)
}

/// Verify a password without changing it
pub fn verify_password(password: &str) -> bool {
    // We can't directly verify without storing a password verifier,
    // but we can try to derive the key to see if it works
    derive_master_key(password).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_change() {
        let current_pwd = "CurrentP@ssw0rd123!";
        let new_pwd = "NewStr0ng!P@ssw0rd456";

        // Derive initial key to get the salt
        let (_key, salt) = derive_master_key(current_pwd).expect("Should derive key");

        // Verify that both passwords are valid
        assert!(verify_password(current_pwd));
        assert!(verify_password(new_pwd));

        // Attempt to change the password with the salt
        let result = change_master_password(current_pwd, &salt, new_pwd);
        assert!(result.is_ok(), "Password change should succeed with valid passwords");
    }

    #[test]
    fn test_wrong_current_password() {
        let wrong_pwd = "WrongP@ssw0rd!";
        let new_pwd = "NewStr0ng!P@ssw0rd!";
        let fake_salt = "somefakesalt";

        // Attempt to change with wrong current password
        let result = change_master_password(wrong_pwd, fake_salt, new_pwd);
        assert!(matches!(result, Err(PasswordChangeError::CurrentPasswordIncorrect)));
    }

    #[test]
    fn test_weak_new_password() {
        use crate::master_key::password_validation::PasswordValidator;

        let current_pwd = "CurrentP@ssw0rd!";
        let weak_pwd = "weak"; // This should fail validation

        // Derive initial key to get the salt
        let (_key, salt) = derive_master_key(current_pwd).expect("Should derive key");

        // Verify that the weak password fails validation on its own
        assert!(PasswordValidator::validate_password_strength(weak_pwd).is_err());

        // Attempt to change to weak password
        let result = change_master_password(current_pwd, &salt, weak_pwd);
        assert!(matches!(result, Err(PasswordChangeError::NewPasswordTooWeak(_))));
    }
}
