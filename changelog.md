# Version 1.2.8
### What's New
* Updates to README
* Merge pull request #66 from videmort/master: Update Spanish literal
* Merge pull request #65 from nataze/backup-PIN: PIN fallback when fingerprint isn't supported
* **Bug fix** for issue #54
    * Allow state loss of dialog fragment
* Changed manifest permission check
    * Now using cordova.hasPermission()
    * Removed dependency on android.support.v4 library
        * Removed build-extras.gradle

# Version 1.2.7
### What's New
* Improved German translations - pull request #58
* **Bug fix** for issue #57 - deleting secret key in Android Keystore.
* Added fixed error codes - pull request #56
* Added `ERRORS` JSON Object to the FingerprintAuth class prototype with the following fields corresponding to the new fixed error codes:
    ```
     BAD_PADDING_EXCEPTION,
     CERTIFICATE_EXCEPTION,
     FINGERPRINT_CANCELLED,
     FINGERPRINT_DATA_NOT_DELETED,
     FINGERPRINT_ERROR,
     FINGERPRINT_NOT_AVAILABLE,
     FINGERPRINT_PERMISSION_DENIED,
     FINGERPRINT_PERMISSION_DENIED_SHOW_REQUEST,
     ILLEGAL_BLOCK_SIZE_EXCEPTION,
     INIT_CIPHER_FAILED,
     INVALID_ALGORITHM_PARAMETER_EXCEPTION,
     IO_EXCEPTION,
     JSON_EXCEPTION,
     MINIMUM_SDK,
     MISSING_ACTION_PARAMETERS,
     MISSING_PARAMETERS,
     NO_SUCH_ALGORITHM_EXCEPTION,
     SECURITY_EXCEPTION
    ```

### Breaking Changes
* Changed error message for cancelled from "Cancelled" to fixed error code `FingerprintAuth.ERRORS.FINGERPRINT_CANCELLED`

# Version 1.2.6
### What's New
* **Bug fix** for issue #61 - added missing source-file element for German strings to plugin.xml

# Version 1.2.5
### What's New
* **Bug fix** for issue #46 - Dismiss fragment in a safer way

# Version 1.2.4
### What's New
* Updated `build-extras.gradle` to use Android SDK 25.

# Version 1.2.3
### What's New
* German translations

# Version 1.2.2
### What's New
* **Bug fix** - `isAvailable()` returning message "Missing required parameters".
* Added `build-extras.gradle` to add dependency `com.android.support:support-v4:23.0.0`  to check for manifest permissions.
* Added check and request for permission to use fingerprints.
* Added error handling for `SecurityException`

# Version 1.2.0
### What's New
* Removed `FingerprintAuth.CipherMode`
* Removed `FingerprintAuth.show() ` in favor of separate actions for encrypt and decrypt
* Added `FingerprintAuth.encrypt()`
* Added `FingerprintAuth.decrypt()`
* Made `username` optional
* `token` is required for `decrypt()`

### Breaking Changes
* Removed `FingerprintAuth.CipherMode`
* Removed `FingerprintAuth.show() ` in favor of separate actions for encrypt and decrypt


# Version 1.1.0
Introducing encryption and decryption of user credentials.
### What's New
* **Added parameters to the FingerprintAuth Config Object**

| Param | Type | Description |
| --- | --- | --- |
| username | String | (REQUIRED) Used to create credential string for encrypted token and as alias to retrieve the cipher. |
| cipherMode | FingerprintAuth.CipherMode | (REQUIRED) Used to determine if plugin should encrypt or decrypt after authentication. <br/><ul><li>FingerprintAuth.CipherMode.ENCRYPT</li><li>FingerprintAuth.CipherMode.DECRYPT</li></ul>|
| password | String |  Used to create credential string for encrypted token |
| token | String  | Used to create credential string for encrypted token. |

* **Changed FingerprintAuth.show() Result fields**

| Param | Type  | Description |
| --- | --- | ---  |
| withFingerprint | boolean | `true` if user authenticated using a fingerprint |
| withBackup | boolean | `true` if user used the backup credentials activity to authenticate. |
| cipherMode | FingerprintAuth.CipherMode | Pass through parameter from config object. |
| token | String | Will contain the base64 encoded credentials if `withFingerprint == true` and `cipherMode == FingerprintAuth.CipherMode.ENCRYPT`. |
| password | String | Will contain the decrypted password if `withFingerprint == true` and `cipherMode == FingerprintAuth.CipherMode.DECRYPT` 

* **New method FingerprintAuth.delete() to delete the cipher used to encrypt/decrypt user credentials.**

### Breaking changes

* Removed `clientSecret` parameter from the FingerprintAuth Config Object.
* Added new **required parameters** `cipherMode` and `username`.
* FingerprintAuth.show() result `withFingerprint` is now a boolean.  You will need to obtain the encrypted token from the `token` field.
* FingerprintAuth.show() result `withPassword` was changed to `withBackup`
