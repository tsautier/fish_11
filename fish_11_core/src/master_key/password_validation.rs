//! Password strength validation module for master key system
//!
//! Provides functions to validate the strength of passwords used for master key derivation.

//use std::collections::HashSet;

/// Minimum password length requirement
const MIN_PASSWORD_LENGTH: usize = 12;

/// Minimum number of character classes required
const MIN_CHARACTER_CLASSES: usize = 3;

/// A comprehensive password strength validator
pub struct PasswordValidator;

impl PasswordValidator {
    /// Validate password strength according to security requirements
    ///
    /// # Arguments
    /// * `password` - The password to validate
    ///
    /// # Returns
    /// * `Result<(), String>` - Ok if password is strong enough, Err with description otherwise
    pub fn validate_password_strength(password: &str) -> Result<(), String> {
        // Check minimum length
        if password.len() < MIN_PASSWORD_LENGTH {
            return Err(format!(
                "Password must be at least {} characters long",
                MIN_PASSWORD_LENGTH
            ));
        }

        // Check for character diversity
        let char_classes = Self::count_character_classes(password);
        if char_classes < MIN_CHARACTER_CLASSES {
            return Err(format!(
                "Password must contain at least {} of the following: lowercase, uppercase, digits, special characters",
                MIN_CHARACTER_CLASSES
            ));
        }

        // Check against common passwords/patterns
        if Self::is_common_password(password) {
            return Err("Password is too common or predictable".to_string());
        }

        // Check for sequential characters (e.g., "abcdef", "123456")
        if Self::has_sequential_pattern(password) {
            return Err(
                "Password contains sequential characters which are easily guessable".to_string()
            );
        }

        // Check for repeated characters (e.g., "aaaaaa")
        if Self::has_repeated_pattern(password) {
            return Err(
                "Password contains repeated characters which are easily guessable".to_string()
            );
        }

        // Check for keyboard patterns (e.g., "qwerty", "asdfgh")
        if Self::has_keyboard_pattern(password) {
            return Err(
                "Password contains common keyboard patterns which are easily guessable".to_string()
            );
        }

        Ok(())
    }

    /// Count the number of different character classes in the password
    fn count_character_classes(password: &str) -> usize {
        let mut has_lowercase = false;
        let mut has_uppercase = false;
        let mut has_digit = false;
        let mut has_special = false;

        for c in password.chars() {
            if c.is_lowercase() {
                has_lowercase = true;
            } else if c.is_uppercase() {
                has_uppercase = true;
            } else if c.is_ascii_digit() {
                has_digit = true;
            } else if !c.is_alphanumeric() {
                has_special = true;
            }
        }

        [has_lowercase, has_uppercase, has_digit, has_special].iter().filter(|&&b| b).count()
    }

    /// Check if the password is a common weak password
    fn is_common_password(password: &str) -> bool {
        let lower_pass = password.to_lowercase();
        let common_passwords = [
            "password",
            "123456",
            "qwerty",
            "abc123",
            "password123",
            "admin",
            "letmein",
            "welcome",
            "monkey",
            "1234567890",
            "password1",
            "trustno1",
            "dragon",
            "baseball",
            "football",
            "iloveyou",
            "princess",
            "rockyou",
            "abc123",
            "nicole",
            "daniel",
            "babygirl",
            "qwerty",
            "lovely",
            "123456",
            "hello",
            "mother",
            "mylove",
            "sunshine",
            "shadow",
            "ashley",
            "michael",
            "angela",
            "cookie",
            "summer",
            "charlie",
            "loves",
            "corazon",
            "hello123",
            "harley",
            "robert",
            "danielle",
            "forever",
            "family",
            "jonathan",
            "computer",
            "987654",
            "jessica",
            "michelle",
            "sakura",
            "jennifer",
            "superman",
            "123456789",
            "12345",
            "1234567",
            "12345678",
            "1234567890",
            "qwerty",
            "abc123",
            "football",
            "monkey",
            "letmein",
            "trustno1",
            "dragon",
            "baseball",
            "master",
            "magazine",
            "technician",
            "michael",
            "internet",
        ];

        common_passwords.iter().any(|&common| lower_pass.contains(common))
    }

    /// Check if the password has sequential patterns
    fn has_sequential_pattern(password: &str) -> bool {
        let chars: Vec<char> = password.chars().collect();

        // Check for increasing sequences (e.g., "abc", "123")
        for i in 0..chars.len().saturating_sub(2) {
            let c1 = chars[i] as u32;
            let c2 = chars[i + 1] as u32;
            let c3 = chars[i + 2] as u32;

            if c2 == c1 + 1 && c3 == c2 + 1 {
                return true;
            }
        }

        // Check for decreasing sequences (e.g., "cba", "321")
        for i in 0..chars.len().saturating_sub(2) {
            let c1 = chars[i] as u32;
            let c2 = chars[i + 1] as u32;
            let c3 = chars[i + 2] as u32;

            if c2 == c1 - 1 && c3 == c2 - 1 {
                return true;
            }
        }

        false
    }

    /// Check if the password has repeated patterns
    fn has_repeated_pattern(password: &str) -> bool {
        let chars: Vec<char> = password.chars().collect();

        // Check for repeated characters (e.g., "aaa", "111")
        for i in 0..chars.len().saturating_sub(2) {
            if chars[i] == chars[i + 1] && chars[i] == chars[i + 2] {
                return true;
            }
        }

        // Check for repeated substrings (e.g., "abcabc")
        if password.len() >= 6 {
            for len in 2..=(password.len() / 2) {
                for i in 0..=(password.len() - 2 * len) {
                    let substring = &password[i..i + len];
                    let next_substring = &password[i + len..i + 2 * len];

                    if substring == next_substring {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if the password has keyboard patterns
    fn has_keyboard_pattern(password: &str) -> bool {
        let lower_pass = password.to_lowercase();
        let keyboard_patterns = [
            "qwerty",
            "asdfgh",
            "zxcvbn",
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "123456",
            "654321",
            "!@#$%^",
            "poiu",
            "lkjh",
            "mnbvcx",
        ];

        keyboard_patterns.iter().any(|&pattern| {
            lower_pass.contains(pattern)
                || lower_pass.contains(&pattern.chars().rev().collect::<String>())
        })
    }

    /// Calculate a basic password strength score (0-100)
    pub fn calculate_strength_score(password: &str) -> u8 {
        let mut score = 0u8;

        // Length contributes up to 30 points
        score += (password.len() as u8).min(30);

        // Character variety contributes up to 40 points
        let char_classes = Self::count_character_classes(password);
        score += (char_classes as u8) * 10;

        // Deduct points for common patterns
        if Self::is_common_password(password) {
            score = score.saturating_sub(20);
        }
        if Self::has_sequential_pattern(password) {
            score = score.saturating_sub(15);
        }
        if Self::has_repeated_pattern(password) {
            score = score.saturating_sub(15);
        }
        if Self::has_keyboard_pattern(password) {
            score = score.saturating_sub(10);
        }

        // Ensure score is between 0 and 100
        score.min(100)
    }

    /// Get a human-readable strength rating
    pub fn get_strength_rating(password: &str) -> &'static str {
        let score = Self::calculate_strength_score(password);

        match score {
            0..=20 => "Very Weak",
            21..=40 => "Weak",
            41..=60 => "Fair",
            61..=80 => "Good",
            81..=100 => "Strong",
            _ => "Unknown", // Should not happen
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_passwords() {
        let weak_passwords =
            ["password", "123456", "abc", "qwerty", "aaaaaa", "123456789", "abcdef", "password123"];

        for pwd in weak_passwords.iter() {
            assert!(
                PasswordValidator::validate_password_strength(pwd).is_err(),
                "Password '{}' should be rejected",
                pwd
            );
        }
    }

    #[test]
    fn test_strong_passwords() {
        let strong_passwords =
            ["MyStr0ng!Passw0rd", "C0mpl3x&P@ssw0rd!", "S3cur3_K3y!2025", "P@ssw0rd_FiSH11#"];

        for pwd in strong_passwords.iter() {
            assert!(
                PasswordValidator::validate_password_strength(pwd).is_ok(),
                "Password '{}' should be accepted",
                pwd
            );
        }
    }

    #[test]
    fn test_strength_score() {
        assert_eq!(PasswordValidator::calculate_strength_score("password"), 0); // Very weak
        assert!(PasswordValidator::calculate_strength_score("MyStr0ng!Passw0rd") > 70); // Strong
    }

    #[test]
    fn test_strength_rating() {
        assert_eq!(PasswordValidator::get_strength_rating("password"), "Very Weak");
        assert_eq!(PasswordValidator::get_strength_rating("MyStr0ng!Passw0rd"), "Strong");
    }
}
