use anyhow::{bail, Result};
use core_foundation::{
    base::{CFType, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFDictionary,
    number::CFNumber,
    string::CFString,
};
use core_foundation_sys::base::CFTypeRef;
use core_foundation_sys::data::CFDataRef;
use core_foundation_sys::string::CFStringRef;
use security_framework_sys::access_control::kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly;
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrService, kSecClass,
    kSecClassGenericPassword, kSecMatchLimit, kSecReturnData, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};

extern "C" {
    static kSecAttrAccessible: CFStringRef;
}

const SERVICE: &str = "com.hashnet.csid";

pub fn store_device_secret(account: &str, secret: &[u8]) -> Result<()> {
    // Stores a secret byte slice bound to a specific account key inside the secure macOS Keychain.
    let _ = delete_device_secret(account);

    let query: Vec<(CFString, CFType)> = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(SERVICE).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessible) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly).into_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecValueData) },
            CFData::from_buffer(secret).into_CFType(),
        ),
    ];

    let dict = CFDictionary::from_CFType_pairs(&query);
    let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
    if status != 0 {
        bail!("SecItemAdd failed with OSStatus {}", status);
    }
    Ok(())
}

pub fn load_device_secret(account: &str) -> Result<Vec<u8>> {
    // Retrieves a secret byte vector bound to a specific account key from the secure macOS Keychain.
    let query: Vec<(CFString, CFType)> = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(SERVICE).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecMatchLimit) },
            CFNumber::from(1_i32).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
            CFBoolean::from(true).into_CFType(),
        ),
    ];

    let dict = CFDictionary::from_CFType_pairs(&query);
    let mut result: CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };

    if status == -25300 {
        bail!("key not found in keychain");
    }
    if status != 0 {
        bail!("SecItemCopyMatching failed with OSStatus {}", status);
    }

    let data: CFData = unsafe { CFData::wrap_under_create_rule(result as CFDataRef) };
    Ok(data.bytes().to_vec())
}

pub fn delete_device_secret(account: &str) -> Result<()> {
    // Deletes a secret entry bound to a specific account key from the secure macOS Keychain.
    let query: Vec<(CFString, CFType)> = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(SERVICE).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account).into_CFType(),
        ),
    ];

    let dict = CFDictionary::from_CFType_pairs(&query);
    let status = unsafe { SecItemDelete(dict.as_concrete_TypeRef()) };
    if status != 0 && status != -25300 {
        bail!("SecItemDelete failed with OSStatus {}", status);
    }
    Ok(())
}

/// Store PersonalNetworkKey (32-byte key material) in Keychain
pub fn store_pnk(key_bytes: &[u8; 32]) -> Result<()> {
    // Stores the 32-byte Personal Network Key (PNK) material inside the secure macOS Keychain.
    let _ = delete_pnk();

    let query: Vec<(CFString, CFType)> = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(SERVICE).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from("pnk").into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessible) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly).into_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecValueData) },
            CFData::from_buffer(key_bytes).into_CFType(),
        ),
    ];

    let dict = CFDictionary::from_CFType_pairs(&query);
    let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
    if status != 0 {
        bail!("SecItemAdd failed for PNK with OSStatus {}", status);
    }
    Ok(())
}

/// Load PersonalNetworkKey (32-byte key material) from Keychain
pub fn load_pnk() -> Result<[u8; 32]> {
    // Retrieves the 32-byte Personal Network Key (PNK) material from the secure macOS Keychain.
    let query: Vec<(CFString, CFType)> = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(SERVICE).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from("pnk").into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecMatchLimit) },
            CFNumber::from(1_i32).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
            CFBoolean::from(true).into_CFType(),
        ),
    ];

    let dict = CFDictionary::from_CFType_pairs(&query);
    let mut result: CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };

    if status == -25300 {
        bail!("PNK not found in keychain");
    }
    if status != 0 {
        bail!("SecItemCopyMatching failed for PNK with OSStatus {}", status);
    }

    let data: CFData = unsafe { CFData::wrap_under_create_rule(result as CFDataRef) };
    let bytes = data.bytes();
    if bytes.len() != 32 {
        bail!("PNK must be 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

/// Delete PersonalNetworkKey from Keychain
pub fn delete_pnk() -> Result<()> {
    // Deletes the Personal Network Key (PNK) entry from the secure macOS Keychain.
    let query: Vec<(CFString, CFType)> = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(SERVICE).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from("pnk").into_CFType(),
        ),
    ];

    let dict = CFDictionary::from_CFType_pairs(&query);
    let status = unsafe { SecItemDelete(dict.as_concrete_TypeRef()) };
    if status != 0 && status != -25300 {
        bail!("SecItemDelete failed for PNK with OSStatus {}", status);
    }
    Ok(())
}
