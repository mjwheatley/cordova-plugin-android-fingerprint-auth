package com.cordova.plugin.android.fingerprintauth;

import org.apache.cordova.CordovaWebView;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.util.Base64;
import android.util.Log;

import com.loxone.kerberos.MainActivity;
import com.loxone.kerberos.R;

import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.Executor;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG;
import static androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK;
import static androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL;

@TargetApi(23)
public class FingerprintAuth extends CordovaPlugin {
    public static final String TAG = "FingerprintAuth";
    public static String packageName;

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    public static final String FINGERPRINT_PREF_IV = "aes_iv";
    private static final int PERMISSIONS_REQUEST_FINGERPRINT = 346437;

    public static Context mContext;
    public static Activity mActivity;
    private MainActivity mMainActivity;
    public KeyguardManager mKeyguardManager;
    public static KeyStore mKeyStore;
    public static KeyGenerator mKeyGenerator;
    public static Cipher mCipher;

    public static CallbackContext mCallbackContext;
    public static PluginResult mPluginResult;

    //Biometric Manager
    private Executor executor;
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.PromptInfo promptInfo;
    private BiometricManager mBiometricManager;
    public enum PluginAction {
        AVAILABILITY,
        ENCRYPT,
        DECRYPT,
        DELETE
    }

    public enum PluginError {
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
    }


    /**
     * Alias for our key in the Android Key Store
     */
    private static String mClientId;
    /**
     * Used to encrypt token
     */
    private static String mUsername = "";
    private static String mClientSecret;
    private static boolean mCipherModeCrypt;

    /**
     * Options
     */
    public static boolean mDisableBackup = false;
    private static boolean mUserAuthRequired = true;
    public static String mDialogTitle;
    public static String mDialogMessage;
    public static String mDialogHint;

    /**
     * Constructor.
     */
    public FingerprintAuth() {
    }

    /**
     * Sets the context of the Command. This can then be used to do things like
     * get file paths associated with the Activity.
     *
     * @param cordova The context of the main Activity.
     * @param webView The CordovaWebView Cordova is running in.
     */
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        Log.v(TAG, "Init FingerprintAuth");

        packageName = cordova.getActivity().getApplicationContext().getPackageName();
        mPluginResult = new PluginResult(PluginResult.Status.NO_RESULT);
        mActivity = cordova.getActivity();
        mContext = cordova.getActivity().getApplicationContext();

        if (android.os.Build.VERSION.SDK_INT < 23) {
            return;
        }

        mKeyguardManager = cordova.getActivity().getSystemService(KeyguardManager.class);
        mBiometricManager = BiometricManager.from(cordova.getActivity().getApplicationContext());

        try {
            mKeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to get an instance of KeyStore", e);
        }

        try {
           mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        }
    }

    /**
     * Executes the request and returns PluginResult.
     *
     * @param action          The action to execute.
     * @param args            JSONArry of arguments for the plugin.
     * @param callbackContext The callback id used when calling back into JavaScript.
     * @return A PluginResult object with a status and message.
     */
    public boolean execute(final String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        mCallbackContext = callbackContext;

        if (android.os.Build.VERSION.SDK_INT < 23) {
            Log.e(TAG, "minimum SDK version 23 required");
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            mCallbackContext.error(PluginError.MINIMUM_SDK.name());
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        }

        Log.v(TAG, "FingerprintAuth action: " + action);
        if(action != null){
            final JSONObject arg_object = args.getJSONObject(0);
            JSONObject resultJson = new JSONObject();
            if (!action.equalsIgnoreCase("availability")) {
                if (!arg_object.has("clientId")) {
                    Log.e(TAG, "Missing required parameters.");
                    mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                    mCallbackContext.error(PluginError.MISSING_PARAMETERS.name());
                    mCallbackContext.sendPluginResult(mPluginResult);
                    return true;
                }

                mClientId = arg_object.getString("clientId");

                if (arg_object.has("username")) {
                    mUsername = arg_object.getString("username");
                }

                if (arg_object.has("disableBackup")) {
                    mDisableBackup = arg_object.getBoolean("disableBackup");
                }

                if (arg_object.has("dialogTitle")) {
                    mDialogTitle = arg_object.getString("dialogTitle");
                }
                if (arg_object.has("dialogMessage")) {
                    mDialogMessage = arg_object.getString("dialogMessage");
                }
                if (arg_object.has("dialogHint")) {
                    mDialogHint = arg_object.getString("dialogHint");
                }
            }
            switch (action){
                case "availability" :
                    checkAndRequestPermission(Manifest.permission.USE_FINGERPRINT,
                            PERMISSIONS_REQUEST_FINGERPRINT);
                    return true;
                case "encrypt" :
                    mCipherModeCrypt = true;
                    String password = "";
                    if (arg_object.has("password")) {
                        password = arg_object.getString("password");
                    }
                    mClientSecret = mClientId + mUsername + ":" + password;
                    showPrompt();
                    return true;
                case "decrypt" :
                    mCipherModeCrypt = false;
                    if (arg_object.has("token")) {
                        mClientSecret = arg_object.getString("token");
                    } else {
                        Log.e(TAG, "Missing required parameters for specified action.");
                        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                        mCallbackContext.error(PluginError.MISSING_ACTION_PARAMETERS.name());
                        mCallbackContext.sendPluginResult(mPluginResult);
                        return true;
                    }
                    showPrompt();
                    return true;
                case "delete" :
                    boolean ivDeleted = false;
                    boolean secretKeyDeleted = false;
                    try {
                        mKeyStore.deleteEntry(mClientId);
                        secretKeyDeleted = true;
                        ivDeleted = deleteIV();
                    } catch (KeyStoreException e) {
                        Log.e(TAG, "Error while deleting SecretKey.");
                    }

                    if (ivDeleted && secretKeyDeleted) {
                        mPluginResult = new PluginResult(PluginResult.Status.OK);
                        mCallbackContext.success();
                    } else {
                        Log.e(TAG, "Error while deleting Fingerprint data.");
                        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                        mCallbackContext.error(PluginError.FINGERPRINT_DATA_NOT_DELETED.name());
                    }
                    mCallbackContext.sendPluginResult(mPluginResult);
                    return true;
                default:
            }


        }
        return false;
    }

    private void showPrompt(){
        if (isFingerprintAuthAvailable()) { //true
            SecretKey key = getSecretKey();
            if (key == null) {
                if (createKey()) {
                    key = getSecretKey();
                }
            }
            if (key != null) {

            cordova.getActivity().runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    executor = ContextCompat.getMainExecutor(cordova.getActivity().getApplicationContext());
                    mMainActivity = (MainActivity) cordova.getActivity();  //git@github.com:ReallySmallSoftware/cordova-plugin-android-fragmentactivity.git

                    biometricPrompt = new BiometricPrompt(mMainActivity, executor, new BiometricPrompt.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationError(int errorCode,
                                                          @NonNull CharSequence errString) {
                            super.onAuthenticationError(errorCode, errString);
                            Log.i(TAG, 	"Authentication error: " + errString + " Code: " + errorCode); //Cancel = 13 //Too much attempts = 7
                            FingerprintAuth.onError("");
                        }

                        @Override
                        public void onAuthenticationSucceeded(
                                @NonNull BiometricPrompt.AuthenticationResult result) {
                            super.onAuthenticationSucceeded(result);
                            Log.i(TAG, 	"Login successful!");
                            FingerprintAuth.onAuthenticatedNew(result);
                        }

                        @Override
                        public void onAuthenticationFailed() {
                            super.onAuthenticationFailed();
                            Log.i(TAG, 	"Authentication error!");
                        }
                    });

                    Resources res = mActivity.getResources();
                    //text in strings speichern!!!
                    if(mDisableBackup){
                        //authentication for encrypton
                        promptInfo = new BiometricPrompt.PromptInfo.Builder()
                                .setTitle(mDialogTitle)
                                .setSubtitle(mDialogMessage)
                                .setDescription(mDialogHint)
                                .setNegativeButtonText(res.getString(R.string.cancel))
                                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                                .build();
                        //starts Prompt Dialog
                        initCipher();
                        biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(mCipher));
                    } else {
                        //only authentication for Appstart
                        promptInfo = new BiometricPrompt.PromptInfo.Builder()
                                .setTitle(mDialogTitle)
                                .setSubtitle(mDialogMessage)
                                .setDescription(mDialogHint)
                                .setAllowedAuthenticators(BIOMETRIC_WEAK|DEVICE_CREDENTIAL) //strong and credentials not supportet <= A10
                                .setConfirmationRequired(false)
                                .build();
                        biometricPrompt.authenticate(promptInfo);
                    }
                }
            });
               mPluginResult.setKeepCallback(true);
            } else {
                mCallbackContext.sendPluginResult(mPluginResult);
            }
        } else {
            Log.e(TAG, "Fingerprint authentication not available");
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            mCallbackContext.error(PluginError.FINGERPRINT_NOT_AVAILABLE.name());
            mCallbackContext.sendPluginResult(mPluginResult);
        }
    }

    //prompt to enroll fingerprint setting is missing
    private boolean isFingerprintAuthAvailable() throws SecurityException {
        switch (mBiometricManager.canAuthenticate(BIOMETRIC_STRONG)) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                Log.d(TAG, "App can authenticate using biometrics.");
                //workarround to prevent using face ID, currently no way to detect typ
                //FingerprintManager fingerPrintManager = cordova.getActivity().getApplicationContext().getSystemService(FingerprintManager.class);
                //return fingerPrintManager.hasEnrolledFingerprints();
                return true;
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                Log.e(TAG, "No biometric features available on this device.");
                return false;
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                Log.e(TAG, "Biometric features are currently unavailable.");
                return false;
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                Log.e(TAG, "No Biometrics enrolled.");
                return false;
        }
        return false;
    }

    private void sendAvailabilityResult() {
        String errorMessage = null;
        JSONObject resultJson = new JSONObject();

        try {
            resultJson.put("isAvailable", isFingerprintAuthAvailable());
            resultJson.put("isHardwareDetected", true);
            resultJson.put("hasEnrolledFingerprints", true);
            mPluginResult = new PluginResult(PluginResult.Status.OK);
            mCallbackContext.success(resultJson);
            mCallbackContext.sendPluginResult(mPluginResult);
        } catch (JSONException e) {
            Log.e(TAG, "Availability Result Error: JSONException: " + e.toString());
            errorMessage = PluginError.JSON_EXCEPTION.name();
        } catch (SecurityException e) {
            Log.e(TAG, "Availability Result Error: SecurityException: " + e.toString());
            errorMessage = PluginError.SECURITY_EXCEPTION.name();
        }
        if (null != errorMessage) {
            Log.e(TAG, errorMessage);
            setPluginResultError(errorMessage);
        }
    }

    private void checkAndRequestPermission(String manifestPermissionName,
                                           int requestCallbackConst) {
        if (ContextCompat.checkSelfPermission(mContext,
                manifestPermissionName) != PackageManager.PERMISSION_GRANTED) {

            // Should we show an explanation?
            if (ActivityCompat.shouldShowRequestPermissionRationale(mActivity,
                    manifestPermissionName)) {

                // Show an explanation to the user *asynchronously* -- don't block
                // this thread waiting for the user's response! After the user
                // sees the explanation, try again to request the permission.
                Log.e(TAG, "Fingerprint permission denied. Show request permission rationale.");
                setPluginResultError(PluginError.FINGERPRINT_PERMISSION_DENIED_SHOW_REQUEST.name());
            } else {

                // No explanation needed, we can request the permission.
                ActivityCompat.requestPermissions(mActivity,
                        new String[]{manifestPermissionName},
                        requestCallbackConst);

                // requestCallbackConst is an
                // app-defined int constant. The callback method gets the
                // result of the request.
            }
        } else {
            sendAvailabilityResult();
        }
    }

    @Override
    public void onRequestPermissionResult(int requestCode, String[] permissions,
                                          int[] grantResults) throws JSONException {
        super.onRequestPermissionResult(requestCode, permissions, grantResults);
        switch (requestCode) {
            case PERMISSIONS_REQUEST_FINGERPRINT: {
                // If request is cancelled, the result arrays are empty.
                if (grantResults.length > 0
                        && grantResults[0] == PackageManager.PERMISSION_GRANTED) {

                    // permission was granted, yay! Do the
                    // contacts-related task you need to do.
                    sendAvailabilityResult();
                } else {

                    // permission denied, boo! Disable the
                    // functionality that depends on this permission.
                    Log.e(TAG, "Fingerprint permission denied.");
                    setPluginResultError(PluginError.FINGERPRINT_PERMISSION_DENIED.name());
                }
                return;
            }
        }
    }

    /**
     * Initialize the {@link Cipher} instance with the created key in the {@link #createKey()}
     * method.
     *
     * @return {@code true} if initialization is successful, {@code false} if the lock screen has
     * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
     * the key was generated.
     */
    private static boolean initCipher() {
        boolean initCipher = false;
        String errorMessage = "";
        String initCipherExceptionErrorPrefix = "Failed to init Cipher: ";
        byte[] mCipherIV;

        try {
            SecretKey key = getSecretKey();

            if (mCipherModeCrypt) {
                mCipher.init(Cipher.ENCRYPT_MODE, key);
                mCipherIV = mCipher.getIV();
                setStringPreference(mContext, mClientId + mUsername,
                        FINGERPRINT_PREF_IV, new String(Base64.encode(mCipherIV, Base64.NO_WRAP)));
            } else {
                mCipherIV = Base64.decode(getStringPreference(mContext, mClientId + mUsername,
                        FINGERPRINT_PREF_IV), Base64.NO_WRAP);
                IvParameterSpec ivspec = new IvParameterSpec(mCipherIV);
                mCipher.init(Cipher.DECRYPT_MODE, key, ivspec);
            }
            initCipher = true;
        } catch (Exception e) {
            errorMessage = initCipherExceptionErrorPrefix + "Exception: " + e.toString();
        }
        if (!initCipher) {
            Log.e(TAG, errorMessage);
        }
        return initCipher;
    }

    public static boolean deleteIV() {
        return deleteStringPreference(mContext, mClientId + mUsername, FINGERPRINT_PREF_IV);
    }

    private static SecretKey getSecretKey() {
        String errorMessage = "";
        String getSecretKeyExceptionErrorPrefix = "Failed to get SecretKey from KeyStore: ";
        SecretKey key = null;
        try {
            mKeyStore.load(null);
            key = (SecretKey) mKeyStore.getKey(mClientId, null);
        } catch (KeyStoreException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix
                    + "KeyStoreException: " + e.toString();
        } catch (CertificateException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix
                    + "CertificateException: " + e.toString();
        } catch (UnrecoverableKeyException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix
                    + "UnrecoverableKeyException: " + e.toString();
        } catch (IOException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix
                    + "IOException: " + e.toString();
        } catch (NoSuchAlgorithmException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix
                    + "NoSuchAlgorithmException: " + e.toString();
        }
        if (key == null) {
            Log.e(TAG, errorMessage);
        }
        return key;
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with fingerprint.
     */
    public static boolean createKey() {
        String errorMessage = "";
        String createKeyExceptionErrorPrefix = "Failed to create key: ";
        boolean isKeyCreated = false;
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            mKeyStore.load(null);
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                mKeyGenerator.init(new KeyGenParameterSpec.Builder(mClientId,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setUserAuthenticationRequired(mUserAuthRequired)
                        //.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL)
                        .setInvalidatedByBiometricEnrollment(false)     //key should not be invalidated on biometric enrollment, only Android 7
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .build());
            }else{
                mKeyGenerator.init(new KeyGenParameterSpec.Builder(mClientId,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setUserAuthenticationRequired(mUserAuthRequired)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .build());
            }
            mKeyGenerator.generateKey();
            isKeyCreated = true;
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, createKeyExceptionErrorPrefix
                    + "NoSuchAlgorithmException: " + e.toString());
            errorMessage = PluginError.NO_SUCH_ALGORITHM_EXCEPTION.name();
        } catch (InvalidAlgorithmParameterException e) {
            Log.e(TAG, createKeyExceptionErrorPrefix
                    + "InvalidAlgorithmParameterException: " + e.toString());
            errorMessage = PluginError.INVALID_ALGORITHM_PARAMETER_EXCEPTION.name();
        } catch (CertificateException e) {
            Log.e(TAG, createKeyExceptionErrorPrefix
                    + "CertificateException: " + e.toString());
            errorMessage = PluginError.CERTIFICATE_EXCEPTION.name();
        } catch (IOException e) {
            Log.e(TAG, createKeyExceptionErrorPrefix
                    + "IOException: " + e.toString());
            errorMessage = PluginError.IO_EXCEPTION.name();
        }
        if (!isKeyCreated) {
            Log.e(TAG, errorMessage);
            setPluginResultError(errorMessage);
        }
        return isKeyCreated;
    }


    public static void onAuthenticatedNew(@NonNull BiometricPrompt.AuthenticationResult result) {
        JSONObject resultJson = new JSONObject();
        String errorMessage = "";
        boolean createdResultJson = false;

        try {
            if (mDisableBackup) { //result.getAuthenticationType() == BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC
                // If the user has authenticated with fingerprint, verify that using cryptography and
                // then return the encrypted (in Base 64) or decrypted mClientSecret
                byte[] bytes;
                if (mCipherModeCrypt) { //encrypt
                    bytes = result.getCryptoObject().getCipher()
                            .doFinal(mClientSecret.getBytes("UTF-8"));
                    String encodedBytes = Base64.encodeToString(bytes, Base64.NO_WRAP);
                    resultJson.put("token", encodedBytes);
                } else {    //decrypt
                    //bytes = result.getCryptoObject().getCipher().doFinal("asdf".getBytes(Charset.defaultCharset()));
                    bytes = result.getCryptoObject().getCipher().doFinal(Base64.decode(mClientSecret, Base64.NO_WRAP));
                    String credentialString = new String(bytes, "UTF-8");
                    String[] credentialArray = credentialString.split(":");
                    if (credentialArray.length == 2) {
                        String username = credentialArray[0];
                        String password = credentialArray[1];
                        if (username.equalsIgnoreCase(mClientId + mUsername)) {
                            resultJson.put("password", password);
                        }
                    }
                }
                resultJson.put("withFingerprint", true);
            } else {
                // Authentication happened with backup password.
                resultJson.put("withBackup", true);
                // If failed to init cipher because of InvalidKeyException, create new key
                if (!initCipher()) {
                    createKey();
                }
            }
            createdResultJson = true;
        } catch (BadPaddingException e) {
            Log.e(TAG, "Failed to encrypt the data with the generated key:"
                    + " BadPaddingException:  " + e.toString());
            errorMessage = PluginError.BAD_PADDING_EXCEPTION.name();
        } catch (IllegalBlockSizeException e) {
            Log.e(TAG, "Failed to encrypt the data with the generated key: "
                    + "IllegalBlockSizeException: " + e.toString());
            errorMessage = PluginError.ILLEGAL_BLOCK_SIZE_EXCEPTION.name();
        } catch (JSONException e) {
            Log.e(TAG, "Failed to set resultJson key value pair: " + e.toString());
            errorMessage = PluginError.JSON_EXCEPTION.name();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        if (createdResultJson) {
            mCallbackContext.success(resultJson);
            mPluginResult = new PluginResult(PluginResult.Status.OK);
        } else {
            mCallbackContext.error(errorMessage);
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        }
        mCallbackContext.sendPluginResult(mPluginResult);
    }

    public static void onCancelled() {
        mCallbackContext.error(PluginError.FINGERPRINT_CANCELLED.name());
    }

    public static void onError(CharSequence errString) {
        mCallbackContext.error(PluginError.FINGERPRINT_ERROR.name());
        Log.e(TAG, errString.toString());
    }

    public static boolean setPluginResultError(String errorMessage) {
        mCallbackContext.error(errorMessage);
        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        return false;
    }

    /**
     * Get a String preference
     *
     * @param context App context
     * @param name    Preference name
     * @param key     Preference key
     * @return Requested preference, if not exist returns null
     */
    public static String getStringPreference(Context context, String name, String key) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        return sharedPreferences.getString(key, null);
    }

    /**
     * Set a String preference
     *
     * @param context App context
     * @param name    Preference name
     * @param key     Preference key
     * @param value   Preference value to be saved
     */
    public static void setStringPreference(Context context, String name, String key, String value) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();

        editor.putString(key, value);
        editor.apply();
    }

    /**
     * Delete a String preference
     *
     * @param context App context
     * @param name    Preference name
     * @param key     Preference key
     * @return Returns true if deleted otherwise false
     */
    public static boolean deleteStringPreference(Context context, String name, String key) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();

        return editor.remove(key).commit();
    }
}
