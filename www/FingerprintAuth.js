function FingerprintAuth() {
}

FingerprintAuth.prototype.show = function (params, successCallback, errorCallback) {
    cordova.exec(
        successCallback,
        errorCallback,
        "FingerprintAuth",  // Java Class
        "authenticate", // action
        [ // Array of arguments to pass to the Java class
            {
                clientId: params.clientId,
                clientSecret: params.clientSecret
            }
        ]
    );
}

FingerprintAuth = new FingerprintAuth();
module.exports = FingerprintAuth;