export const enum IFingerprintAuthErrors {
    BAD_PADDING_EXCEPTION = "BAD_PADDING_EXCEPTION",
    CERTIFICATE_EXCEPTION = "CERTIFICATE_EXCEPTION",
    FINGERPRINT_CANCELLED = "FINGERPRINT_CANCELLED",
    FINGERPRINT_DATA_NOT_DELETED = "FINGERPRINT_DATA_NOT_DELETED",
    FINGERPRINT_ERROR = "FINGERPRINT_ERROR",
    FINGERPRINT_NOT_AVAILABLE = "FINGERPRINT_NOT_AVAILABLE",
    FINGERPRINT_PERMISSION_DENIED = "FINGERPRINT_PERMISSION_DENIED",
    FINGERPRINT_PERMISSION_DENIED_SHOW_REQUEST = "FINGERPRINT_PERMISSION_DENIED_SHOW_REQUEST",
    ILLEGAL_BLOCK_SIZE_EXCEPTION = "ILLEGAL_BLOCK_SIZE_EXCEPTION",
    INIT_CIPHER_FAILED = "INIT_CIPHER_FAILED",
    INVALID_ALGORITHM_PARAMETER_EXCEPTION = "INVALID_ALGORITHM_PARAMETER_EXCEPTION",
    IO_EXCEPTION = "IO_EXCEPTION",
    JSON_EXCEPTION = "JSON_EXCEPTION",
    MINIMUM_SDK = "MINIMUM_SDK",
    MISSING_ACTION_PARAMETERS = "MISSING_ACTION_PARAMETERS",
    MISSING_PARAMETERS = "MISSING_PARAMETERS",
    NO_SUCH_ALGORITHM_EXCEPTION = "NO_SUCH_ALGORITHM_EXCEPTION"
}

/**
 * The Cordova "FingerprintAuth" plugin
 * See {@link https://github.com/mjwheatley/cordova-plugin-android-fingerprint-auth}
 */
interface IFingerprintAuth {

    /**
     * @description Opens a native dialog fragment to use the device hardware fingerprint scanner
     * to authenticate against fingerprints registered for the device.
     *
     * @param {FingerprintAuthIsAvailableSuccess} successCallback - Success callback.
     * @param {string} errorCallback - Error callback.
     */
    isAvailable(successCallback, errorCallback): void;

    /**
     * @description Call encrypt() show the Authentication Dialog.
     *
     * @param {FingerprintAuthConfig} encryptConfig - Encrypt config.
     * @param {FingerprintAuthEncryptSuccess} encryptSuccessCallback - Encrypt success callback.
     * @param {IFingerprintAuthErrors} encryptErrorCallback - Encrypt error callback.
     */
    encrypt(encryptConfig, encryptSuccessCallback, encryptErrorCallback): void;

    /**
     * @description Call decrypt() show the Authentication Dialog.
     *
     * @param {FingerprintAuthConfig} decryptConfig - decryptConfig.
     * @param {FingerprintAuthDecryptSuccess} encryptSuccessCallback - Encrypt success callback.
     * @param {IFingerprintAuthErrors} encryptErrorCallback - Encrypt error callback.
     */
    decrypt(decryptConfig, encryptSuccessCallback, encryptErrorCallback): void;

    /**
     * @description Call delete() when you want to delete the cipher for the user.
     *
     * @param {FingerprintDeleteConfig} config
     * @param {Object} successCallback - Success callback.
     * @param {string} errorCallback - Error callback.
     */
    delete(config, successCallback, errorCallback): void;

}

interface FingerprintAuthIsAvailableSuccess {

    /**
     * @description Fingerprint Authentication Dialog is available for use.
     */
    isAvailable: boolean;

    /**
     * @description Device has hardware fingerprint sensor.
     */
    isHardwareDetected: boolean;

    /**
     * @description Device has any fingerprints enrolled.
     */
    hasEnrolledFingerprints: boolean;

}

interface FingerprintAuthEncryptSuccess {

    /**
     * @description User authenticated using a fingerprint.
     */
    withFingerprint: boolean;

    /**
     * @description User authenticated using backup credentials.
     */
    withBackup: boolean;

    /**
     * @description Will contain the base64 encoded credentials upon successful fingerprint authentication.
     */
    token: string;

}

interface FingerprintAuthDecryptSuccess {

    /**
     * @description User authenticated using a fingerprint.
     */
    withFingerprint: boolean;

    /**
     * @description User authenticated using backup credentials.
     */
    withBackup: boolean;

    /**
     * @description Will contain the decrypted password upon successful fingerprint authentication.
     */
    password: string;

}

interface FingerprintAuthConfig {

    /**
     * @description (REQUIRED) Used as the alias for your app's secret key in the Android Key Store.
     * Also used as part of the Shared Preferences key for the cipher userd to encrypt the user credentials.
     */
    clientId: string;

    /**
     * @description Used to create credential string for encrypted token and as alias to retrieve the cipher.
     */
    username: string;

    /**
     * @description Used to create credential string for encrypted token.
     */
    password: string;

    /**
     * @description Data to be decrypted. Required for decrypt().
     */
    token: string;

    /**
     * @description Set to true to remove the "USE BACKUP" button.
     */
    disableBackup: boolean;

    /**
     * @description The device max is 5 attempts. Set this parameter if you want to allow fewer than 5 attempts.
     */
    maxAttempts: number;

    /**
     * @description Change the language displayed on the authentication dialog.
     * English: "en_US"
     * Italian: "it"
     * Spanish: "es"
     * Russian: "ru"
     * French: "fr"
     * Chinese (Simplified):
     *      "zh_CN"
     *      "zh_SG"
     * Chinese (Traditional):
     *      "zh"
     *      "zh_HK"
     *      "zh_TW"
     *      "zh_MO"
     * Norwegian: "no"
     * Portuguese: "pt"
     * Japanese: "ja"
     * German: "de"
     * Thai: "th"
     * Arabic: "ar"
     */
    locale: string;

    /**
     * @description Require the user to authenticate with a fingerprint to authorize every use of the key.
     * New fingerprint enrollment will invalidate key and require backup authenticate to re-enable the fingerprint authentication dialog.
     */
    userAuthRequired: boolean;

    /**
     * @description Set the title of the fingerprint authentication dialog.
     */
    dialogTitle: string;

    /**
     * @description Set the message of the fingerprint authentication dialog.
     */
    dialogMessage: string;

    /**
     * @description Set the hint displayed by the fingerprint icon on the fingerprint authentication dialog.
     */
    dialogHint: string;

}

interface FingerprintDeleteConfig {

    /**
     * @description Identify which cipher to delete.
     */
    username: string;

    /**
     * @description (REQUIRED) Used as the alias for your key in the Android Key Store.
     */
    clientId: string;

}

declare var FingerprintAuth: IFingerprintAuth;
