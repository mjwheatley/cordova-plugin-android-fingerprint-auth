package com.cordova.plugin.android.fingerprintauth;

import org.apache.cordova.CordovaWebView;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;

import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.DisplayMetrics;
import android.util.Log;

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
import java.util.Locale;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@TargetApi(23)
public class FingerprintAuth extends CordovaPlugin {
    public static final String TAG = "FingerprintAuth";
    public static String packageName;

    private static final String DIALOG_FRAGMENT_TAG = "FpAuthDialog";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    public KeyguardManager mKeyguardManager;
    public FingerprintAuthenticationDialogFragment mFragment;
    public static KeyStore mKeyStore;
    public static KeyGenerator mKeyGenerator;
    public static Cipher mCipher;
    private FingerprintManager mFingerPrintManager;

    public static CallbackContext mCallbackContext;
    public static PluginResult mPluginResult;

    /**
     * Alias for our key in the Android Key Store
     */
    private static String mClientId;
    /**
     * Used to encrypt token
     */
    private static String mUsername;
    private static String mClientSecret;
    private static boolean mCipherModeCrypt;

    /**
     * Options
     */
    private static String mCipherMode;
    public static boolean mDisableBackup = false;
    public static int mMaxAttempts = 6;  // one more than the device default to prevent a 2nd callback
    private String mLangCode = "en_US";
    private static boolean mUserAuthRequired = true;
    public static String mDialogTitle;
    public static String mDialogMessage;
    public static String mDialogHint;
    public static Context mContext;
    public static final String FINGERPRINT_PREF_IV = "aes_iv";

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
        mContext = cordova.getActivity().getApplicationContext();

        if (android.os.Build.VERSION.SDK_INT < 23) {
            return;
        }

        mKeyguardManager = cordova.getActivity().getSystemService(KeyguardManager.class);
        mFingerPrintManager = cordova.getActivity().getApplicationContext().getSystemService(FingerprintManager.class);

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
            mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
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
        Log.v(TAG, "FingerprintAuth action: " + action);
        if (android.os.Build.VERSION.SDK_INT < 23) {
            Log.e(TAG, "minimum SDK version 23 required");
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            mCallbackContext.error("minimum SDK version 23 required");
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        }

        final JSONObject arg_object = args.getJSONObject(0);

        if (action.equals("show")) {
            if (!arg_object.has("clientId") && !arg_object.has("username") || !arg_object.has("cipherMode")) {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error("Missing required parameters");
                mCallbackContext.sendPluginResult(mPluginResult);
                return true;
            }
            mClientId = arg_object.getString("clientId");
            mUsername = arg_object.getString("username");
            mCipherMode = arg_object.getString("cipherMode");

            boolean missingParam = false;
            if (mCipherMode.equalsIgnoreCase("decrypt")) {
                mCipherModeCrypt = false; // Decrypt mode
                if (arg_object.has("token")) {
                    mClientSecret = arg_object.getString("token");
                } else {
                    missingParam = true;
                }
            } else if (mCipherMode.equalsIgnoreCase("encrypt")) {
                mCipherModeCrypt = true; // Encrypt mode
                if (arg_object.has("password")) {
                    String password = arg_object.getString("password");
                    mClientSecret = mUsername + ":" + password;
                } else {
                    missingParam = true;
                }
            }

            if (missingParam) {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error("Missing required parameters for specified cipherMode.");
                mCallbackContext.sendPluginResult(mPluginResult);
                return true;
            }

            if (arg_object.has("disableBackup")) {
                mDisableBackup = arg_object.getBoolean("disableBackup");
            }
            if (arg_object.has("locale")) {
                mLangCode = arg_object.getString("locale");
                Log.d(TAG, "Change language to locale: " + mLangCode);
            }
            if (arg_object.has("maxAttempts")) {
                int maxAttempts = arg_object.getInt("maxAttempts");
                if (maxAttempts < 5) {
                    mMaxAttempts = maxAttempts;
                }
            }
            if (arg_object.has("userAuthRequired")) {
                mUserAuthRequired = arg_object.getBoolean("userAuthRequired");
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

            // Set language
            Resources res = cordova.getActivity().getResources();
            // Change locale settings in the app.
            DisplayMetrics dm = res.getDisplayMetrics();
            Configuration conf = res.getConfiguration();
            // A length of 5 entales a region specific locale string, ex: zh_HK.
            // The two argument Locale constructor signature must be used in that case.
            if (mLangCode.length() == 5) {
                conf.locale = new Locale(mLangCode.substring(0, 2).toLowerCase(),
                    mLangCode.substring(mLangCode.length() - 2).toUpperCase());
            } else {
                conf.locale = new Locale(mLangCode.toLowerCase());
            }
            res.updateConfiguration(conf, dm);

            if (isFingerprintAuthAvailable()) {
                SecretKey key = getSecretKey();
                if (key == null) {
                    if (createKey()) {
                        key = getSecretKey();
                    }
                }
                if (key != null) {
                    cordova.getActivity().runOnUiThread(new Runnable() {
                        public void run() {
                            // Set up the crypto object for later. The object will be authenticated by use
                            // of the fingerprint.
                            mFragment = new FingerprintAuthenticationDialogFragment();
                            if (initCipher()) {
                                mFragment.setCancelable(false);
                                // Show the fingerprint dialog. The user has the option to use the fingerprint with
                                // crypto, or you can fall back to using a server-side verified password.
                                mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
                                mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
                            } else {
                                if (!mDisableBackup) {
                                    // This happens if the lock screen has been disabled or or a fingerprint got
                                    // enrolled. Thus show the dialog to authenticate with their password
                                    mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
                                    mFragment.setStage(FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
                                    mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
                                } else {
                                    mCallbackContext.error("Failed to init Cipher and backup disabled.");
                                    mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                                    mCallbackContext.sendPluginResult(mPluginResult);
                                }
                            }
                        }
                    });
                    mPluginResult.setKeepCallback(true);
                } else {
                    mCallbackContext.sendPluginResult(mPluginResult);
                }
            } else {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error("Fingerprint authentication not available");
                mCallbackContext.sendPluginResult(mPluginResult);
            }
            return true;
        } else if (action.equals("availability")) {
            JSONObject resultJson = new JSONObject();
            resultJson.put("isAvailable", isFingerprintAuthAvailable());
            resultJson.put("isHardwareDetected", mFingerPrintManager.isHardwareDetected());
            resultJson.put("hasEnrolledFingerprints", mFingerPrintManager.hasEnrolledFingerprints());
            mPluginResult = new PluginResult(PluginResult.Status.OK);
            mCallbackContext.success(resultJson);
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        } else if (action.equals("delete")) {
            if (!arg_object.has("clientId") && !arg_object.has("username")) {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error("Missing required parameters");
                mCallbackContext.sendPluginResult(mPluginResult);
                return true;
            }
            mClientId = arg_object.getString("clientId");
            mUsername = arg_object.getString("username");
            boolean deleted = deleteIV();
            if (deleted) {
                mPluginResult = new PluginResult(PluginResult.Status.OK);
                mCallbackContext.success();
            } else {
                JSONObject resultJson = new JSONObject();
                resultJson.put("error", "Error while deleting Fingerprint data.");
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error(resultJson);
            }

            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        }
        return false;
    }

    private boolean isFingerprintAuthAvailable() {
        return mFingerPrintManager.isHardwareDetected() && mFingerPrintManager.hasEnrolledFingerprints();
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
                setStringPreference(mContext, mUsername, FINGERPRINT_PREF_IV, new String(Base64.encode(mCipherIV, Base64.NO_WRAP)));
            } else {
                mCipherIV = Base64.decode(getStringPreference(mContext, mUsername, FINGERPRINT_PREF_IV), Base64.NO_WRAP);
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
        return deleteStringPreference(mContext, mUsername, FINGERPRINT_PREF_IV);
    }

    private static SecretKey getSecretKey() {
        String errorMessage = "";
        String getSecretKeyExceptionErrorPrefix = "Failed to get SecretKey from KeyStore: ";
        SecretKey key = null;
        try {
            mKeyStore.load(null);
            key = (SecretKey) mKeyStore.getKey(mClientId, null);
        } catch (KeyStoreException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "KeyStoreException: " + e.toString();
        } catch (CertificateException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "CertificateException: " + e.toString();
        } catch (UnrecoverableKeyException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "UnrecoverableKeyException: " + e.toString();
        } catch (IOException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "IOException: " + e.toString();
        } catch (NoSuchAlgorithmException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "NoSuchAlgorithmException: " + e.toString();
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
            mKeyGenerator.init(new KeyGenParameterSpec.Builder(mClientId, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(mUserAuthRequired)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            mKeyGenerator.generateKey();
            isKeyCreated = true;
        } catch (NoSuchAlgorithmException e) {
            errorMessage = createKeyExceptionErrorPrefix + "NoSuchAlgorithmException: " + e.toString();
        } catch (InvalidAlgorithmParameterException e) {
            errorMessage = createKeyExceptionErrorPrefix + "InvalidAlgorithmParameterException: " + e.toString();
        } catch (CertificateException e) {
            errorMessage = createKeyExceptionErrorPrefix + "CertificateException: " + e.toString();
        } catch (IOException e) {
            errorMessage = createKeyExceptionErrorPrefix + "IOException: " + e.toString();
        }
        if (!isKeyCreated) {
            Log.e(TAG, errorMessage);
            setPluginResultError(errorMessage);
        }
        return isKeyCreated;
    }

    public static void onAuthenticated(boolean withFingerprint, FingerprintManager.AuthenticationResult result) {
        JSONObject resultJson = new JSONObject();
        String errorMessage = "";
        boolean createdResultJson = false;

        try {
            if (withFingerprint) {
                // If the user has authenticated with fingerprint, verify that using cryptography and
                // then return the encrypted (in Base 64) or decrypted mClientSecret
                byte[] bytes;
                if (mCipherModeCrypt) {
                    bytes = result.getCryptoObject().getCipher().doFinal(mClientSecret.getBytes("UTF-8"));
                    String encodedBytes = Base64.encodeToString(bytes, Base64.NO_WRAP);
                    resultJson.put("token", encodedBytes);
                } else {
                    bytes = result.getCryptoObject().getCipher().doFinal(Base64.decode(mClientSecret, Base64.NO_WRAP));
                    String credentialString =  new String(bytes, "UTF-8");
                    String[] credentialArray = credentialString.split(":");
                    if (credentialArray.length == 2) {
                        String username = credentialArray[0];
                        String password = credentialArray[1];
                        if (username.equalsIgnoreCase(mUsername)) {
                            resultJson.put("password", credentialArray[1]);
                        }
                    }
                }
                resultJson.put("cipherMode", mCipherMode);
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
            errorMessage = "Failed to encrypt the data with the generated key:" + " BadPaddingException:  " + e.toString();
            Log.e(TAG, errorMessage);
        } catch (IllegalBlockSizeException e) {
            errorMessage = "Failed to encrypt the data with the generated key: " + "IllegalBlockSizeException: " + e.toString();
            Log.e(TAG, errorMessage);
        } catch (JSONException e) {
            errorMessage = "Failed to set resultJson key value pair: " + e.toString();
            Log.e(TAG, errorMessage);
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
        mCallbackContext.error("Cancelled");
    }

    public static void onError(CharSequence errString) {
        mCallbackContext.error(errString.toString());
    }

    public static boolean setPluginResultError(String errorMessage) {
        mCallbackContext.error(errorMessage);
        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        return false;
    }

    /**
     * Get a String preference
     *
     * @param context  App context
     * @param name     Preference name
     * @param key      Preference key
     * @return Requested preference, if not exist returns null
     */
    public static String getStringPreference(Context context, String name, String key) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        return sharedPreferences.getString(key, null);
    }

    /**
     * Set a String preference
     *
     * @param context  App context
     * @param name     Preference name
     * @param key      Preference key
     * @param value    Preference value to be saved
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
     * @param context  App context
     * @param name     Preference name
     * @param key      Preference key
     * @return Returns true if deleted otherwise false
     */
    public static boolean deleteStringPreference(Context context, String name, String key) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();

        return editor.remove(key).commit();
    }
}
