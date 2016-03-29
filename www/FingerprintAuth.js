function FingerprintAuth() {}

FingerprintAuth.prototype.show = function (message, successCallback, errorCallback) {
    cordova.exec(successCallback, errorCallback, "FingerprintAuth", "toast", [{message: message}]);
}

FingerprintAuth = new FingerprintAuth();
module.exports = FingerprintAuth;