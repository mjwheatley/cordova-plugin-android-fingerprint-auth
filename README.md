#Installation
`meteor add cordova:cordova-plugin-android-fingerprint-auth`

#Setup
Add preferences to mobile-config.js
```
App.setPreference('android-minSdkVersion', '23');
App.setPreference('android-targetSdkVersion', '23');
```

set compile version and build tools in build.gradle
```
compileSdkVersion 23
buildToolsVersion "23.0.2"
```

#API
##FingerprintAuth.show
```
FingerprintAuth.show({
            clientId: "myAppName",
            clientSecret: "a_very_secret_encryption_key"
        }, successCallback, errorCallback);

/**
 * @return {withFingerprint:base64EncodedString, withPassword:boolean}
 */
function successCallback(result) {
    console.log("successCallback(): " + JSON.stringify(result));
    if (result.withFingerprint) {
        console.log("Successfully authenticated using a fingerprint");
    } else if (result.withPassword) {
        console.log("Authenticated with backup password");
    }
}

function errorCallback(error) {
    console.log(error); // "Fingerprint authentication not available"
}

```
Opens a native dialog fragment to use the device hardware fingerprint scanner to authenticate against fingerprints
registered for the device.

##FingerprintAuth.isAvailable
```
FingerprintAuth.isAvailable(isAvailableSuccess, isAvailableError);

/**
 * @return {
 *      isAvailable:boolean,
 *      isHardwareDetected:boolean,
 *      hasEnrolledFingerprints:boolean
 *   }
 */
function isAvailableSuccess(isAvailable) {
    console.log("FingerprintAuth available: " + JSON.stringify(isAvailable)); // { isAvailable: true }
    if (isAvailable) {
        FingerprintAuth.show({
                    clientId: "myAppName",
                    clientSecret: "a_very_secret_encryption_key"
                }, successCallback, errorCallback);
    }
}

function isAvailableError(message) {
    console.log("isAvailableError(): " + message);
}
```