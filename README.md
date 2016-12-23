#Update to Version 1.1.0
Please consult the [changelog](https://github.com/mjwheatley/cordova-plugin-android-fingerprint-auth/blob/master/changelog.md).

#About
This plugin was created referencing the [Fingerprint Dialog sample](http://developer.android.com/samples/FingerprintDialog/index.html) and the [Confirm Credential sample](http://developer.android.com/samples/ConfirmCredential/index.html) referenced by the [Android 6.0 APIs webpage](http://developer.android.com/about/versions/marshmallow/android-6.0.html).

This plugin will open a native dialog fragment prompting the user to authenticate using their fingerprint.  If the device has a secure lockscreen (pattern, PIN, or password), the user may opt to authenticate using that method as a backup.

#Screenshots
###Fingerprint Authentication Dialog
![Fingerprint Auth Dialog](screenshots/fp_auth_dialog.jpg) ![Fingerprint Auth Dialog Success](screenshots/fp_auth_dialog_success.png) ![Fingerprint Auth Dialog Fail](screenshots/fp_auth_dialog_fail.jpg) ![Fingerprint Auth Dialog Too Many](screenshots/fp_auth_dialog_too_many.jpg) ![Fingerprint Auth Dialog No Backup](screenshots/fp_auth_dialog_no_backup.jpg) ![Fingerprint Auth Dialog No Backup](screenshots/fp_auth_dialog_longer.png)
###Backup Credentials
![Confirm Password](screenshots/confirm_creds_pw.png) ![Confirm PIN](screenshots/confirm_creds_pin.png) ![Confirm Pattern](screenshots/confirm_creds_pattern.png)

#Ionic Installation
`ionic plugin add cordova-plugin-android-fingerprint-auth`

#Meteor.js Installation
`meteor add cordova:cordova-plugin-android-fingerprint-auth`

Add preference to mobile-config.js
```
App.setPreference('android-targetSdkVersion', '23');
```

Set compile version and build tools in build.gradle
```
compileSdkVersion 23
buildToolsVersion "23.0.2"
```

#How to use
- Call `isAvailable` to check the fingerprint status.
- Call `show` show the Authentication Dialog.
- Call `delete` when you want to delete the cipher for the user.

#API Reference
* FingerprintAuth
    * [isAvailable(isAvailableSuccess, isAvailableError)](#module_fingerprintauth.isAvailable) : `function`
    * [show(config, successCallback, errorCallback)](#module_fingerprintauth.show) : `function`
    * [delete(confg, successCallback, errorCallback)](#module_fingerprintauth.delete) : `function`
    * [CipherMode](#module_fingerprintauth.cipherMode) : `enum`


<a name="module_fingerprintauth.isAvailable"></a>
##FingerprintAuth.isAvailable(successCallback, errorCallback)

Opens a native dialog fragment to use the device hardware fingerprint scanner to authenticate against fingerprints
registered for the device.

**Example**

```javascript
FingerprintAuth.isAvailable(isAvailableSuccess, isAvailableError);

/**
 * @return {
 *      isAvailable:boolean,
 *      isHardwareDetected:boolean,
 *      hasEnrolledFingerprints:boolean
 *   }
 */
function isAvailableSuccess(result) {
    console.log("FingerprintAuth available: " + JSON.stringify(result));
    if (result.isAvailable) {
        var config = {}; // See config object for required parameters
        FingerprintAuth.show(config, successCallback, errorCallback);
    }
}

function isAvailableError(message) {
    console.log("isAvailableError(): " + message);
}
```

<a name="module_fingerprintauth.show"></a>
##FingerprintAuth.show(config, successCallback, errorCallback)

###Config Object
| Param | Type | Default | Description |
| --- | --- | --- | --- |
| clientId | String | undefined | (REQUIRED) Used as the alias for your key in the Android Key Store. |
| cipherMode | FingerprintAuth.CipherMode | undefined | (REQUIRED) Used to determine if plugin should encrypt or decrypt after authentication. <br/><ul><li>FingerprintAuth.CipherMode.ENCRYPT</li><li>FingerprintAuth.CipherMode.DECRYPT</li></ul>|
| username | String | undefined | Used to create credential string for encrypted token and as alias to retrieve the cipher. If username is undefined the plugin use only clientId to retrive the cipher stored. |
| password | String | undefined |  Used to create credential string for encrypted token |
| token | String | undefined | Used to create credential string for encrypted token. |
| disableBackup | boolean | false | Set to true to remove the "USE BACKUP" button |
| maxAttempts | number | 5 | The device max is 5 attempts.  Set this parameter if you want to allow fewer than 5 attempts.  |
| locale | String | "en_US" | Change the language displayed on the authentication dialog.<br/><ul><li>English: "en_US"</li><li>Italian: "it"</li><li>Spanish: "es"</li><li>Russian: "ru"</li><li>French: "fr"</li><li>Chinese (Simplified): <ul><li>"zh_CN"</li><li>"zh_SG"</li></ul></li><li>Chinese (Traditional): <ul><li>"zh"</li><li>"zh_HK"</li><li>"zh_TW"</li><li>"zh_MO"</li></ul></li><li>Norwegian: "no"</li><li>Portuguese: "pt"</li><li>Japanese: "ja"</li></ul> |
| userAuthRequired | boolean | true | Require the user to authenticate with a fingerprint to authorize every use of the key.  New fingerprint enrollment will invalidate key and require backup authenticate to re-enable the fingerprint authentication dialog. |
| dialogTitle | String | undefined | Set the title of the fingerprint authentication dialog. |
| dialogMessage | String | undefined | Set the message of the fingerprint authentication dialog. |
| dialogHint | String | undefined | Set the hint displayed by the fingerprint icon on the fingerprint authentication dialog. |

<a name="module_fingerprintauth.cipherMode"></a>
###CipherMode : `Enum`

| Option | Type | Value |
| --- | --- | --- |
| ENCRYPT | String | "encrypt" |
| DECRYPT | String | "decrypt" |

###Result Object
| Param | Type  | Description |
| --- | --- | ---  |
| withFingerprint | boolean | `true` if user authenticated using a fingerprint |
| withBackup | boolean | `true` if user used the backup credentials activity to authenticate. |
| cipherMode | FingerprintAuth.CipherMode | Pass through parameter from config object. |
| token | String | Will contain the base64 encoded credentials if `withFingerprint == true` and `cipherMode == FingerprintAuth.CipherMode.ENCRYPT`. |
| password | String | Will contain the decrypted password if `withFingerprint == true` and `cipherMode == FingerprintAuth.CipherMode.DECRYPT` 

**Example**  

```javascript
var encryptConfig = {
    clientId: "myAppName",
    cipherMode: FingerprintAuth.CipherMode.ENCRYPT,
    username: "currentUser",
    password: "currentUserPassword"
};

var decryptConfig = {
    clientId: "myAppName",
    cipherMode: FingerprintAuth.CipherMode.DECRYPT,
    username: "currentUser",
    token: "base64encodedUserCredentials"
};

FingerprintAuth.show(yourConfig, successCallback, errorCallback);

function successCallback(result) {
    console.log("successCallback(): " + JSON.stringify(result));
    if (result.withFingerprint) {
        if (result.cipherMode === FingerprintAuth.CipherMode.ENCRYPT) {
            console.log("Successfully encrypted credentials.");
            console.log("Encrypted credentials: " + result.token);   
        } else if (result.cipherMode === FingerprintAuth.CipherMode.DECRYPT) {
            console.log("Successfully decrypted user credentials.");
            console.log("password: " + result.password);
        }
    } else if (result.withBackup) {
        console.log("Authenticated with backup password");
    }
}

function errorCallback(error) {
    if (error === "Cancelled") {
        console.log("FingerprintAuth Dialog Cancelled!");
    } else {
        console.log("FingerprintAuth Error: " + error);
    }
}

```


<a name="module_fingerprintauth.delete"></a>
##FingerprintAuth.delete(config, successCallback, errorCallback)

Used to delete a cipher.

#### Config Object
| Param | Type | Default | Description |
| --- | --- | --- | --- |
| clientId | String | undefined | (REQUIRED) Used as the alias for your key in the Android Key Store. |
| username | String | undefined | (REQUIRED) Identify which cipher to delete. |

**Example**

```javascript
FingerprintAuth.delete({
            clientId: "myAppName",
            username: "usernameToDelete"
        }, successCallback, errorCallback);

function successCallback(result) {
    console.log("Successfully deleted cipher: " + JSON.stringify(result));
}

function errorCallback(error) {
    console.log(error);
}
```
