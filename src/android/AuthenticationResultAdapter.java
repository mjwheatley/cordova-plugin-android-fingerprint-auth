package com.cordova.plugin.android.fingerprintauth;

import android.hardware.biometrics.BiometricPrompt;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;

public class AuthenticationResultAdapter {
    private BiometricPrompt.AuthenticationResult biometricResult;
    private FingerprintManagerCompat.AuthenticationResult fingerprintResult;

    public AuthenticationResultAdapter(BiometricPrompt.AuthenticationResult biometricResult) {
        this.biometricResult = biometricResult;
    }

    public AuthenticationResultAdapter(FingerprintManagerCompat.AuthenticationResult fingerprintResult) {
        this.fingerprintResult = fingerprintResult;
    }

    CryptoObjectAdapter getCryptoObject() {
        return this.biometricResult == null
                ? new CryptoObjectAdapter(this.fingerprintResult)
                : new CryptoObjectAdapter(this.biometricResult);
    }
}
