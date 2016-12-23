function FingerprintAuth() {}

FingerprintAuth.prototype.show = function (params, successCallback, errorCallback) {
    cordova.exec(
        successCallback,
        errorCallback,
        "FingerprintAuth",  // Java Class
        "show", // action
        [ // Array of arguments to pass to the Java class
            params
        ]
    );
};

FingerprintAuth.prototype.delete = function (params, successCallback, errorCallback) {
    cordova.exec(
        successCallback,
        errorCallback,
        "FingerprintAuth",  // Java Class
        "delete", // action
        [ // Array of arguments to pass to the Java class
            params
        ]
    );
};

FingerprintAuth.prototype.isAvailable = function (successCallback, errorCallback) {
    cordova.exec(
        successCallback,
        errorCallback,
        "FingerprintAuth",  // Java Class
        "availability", // action
        [{}]
    );
};

FingerprintAuth.prototype.CipherMode = {
    ENCRYPT: "encrypt",
    DECRYPT: "decrypt"
};

FingerprintAuth = new FingerprintAuth();
module.exports = FingerprintAuth;
