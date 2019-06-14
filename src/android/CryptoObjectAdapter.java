package com.cordova.plugin.android.fingerprintauth;

import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;

import javax.crypto.Cipher;

class CryptoObjectAdapter {

    private BiometricPrompt.CryptoObject biometricCryptoObject;
    private FingerprintManagerCompat.CryptoObject fingerprintCryptoObject;

    CryptoObjectAdapter(Cipher mCipher) {
        fingerprintCryptoObject = new FingerprintManagerCompat.CryptoObject(mCipher);
    }

    CryptoObjectAdapter(FingerprintManagerCompat.AuthenticationResult result) {
        fingerprintCryptoObject = result.getCryptoObject();
    }

    CryptoObjectAdapter(BiometricPrompt.AuthenticationResult result) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            biometricCryptoObject = result.getCryptoObject();
        }
    }

    Cipher getCipher() {
        if (this.biometricCryptoObject == null) {
            return this.fingerprintCryptoObject.getCipher();
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return biometricCryptoObject.getCipher();
        }
        return null;
    }
}
