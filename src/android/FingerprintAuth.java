package com.cordova.plugin.android.fingerprintauth;

import org.apache.cordova.CordovaWebView;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;

import android.app.KeyguardManager;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.provider.Settings;
import android.widget.Toast;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class FingerprintAuth extends CordovaPlugin {

	public static final String TAG = "FingerprintAuth";
	public static String packageName;

	private static final String DIALOG_FRAGMENT_TAG = "FpAuthDialog";
	private static final String SECRET_MESSAGE = "Very secret message";
	/** Alias for our key in the Android Key Store */
	private static final String KEY_NAME = "fp_auth_key";

	KeyguardManager mKeyguardManager;
	FingerprintManager mFingerprintManager;
	FingerprintAuthenticationDialogFragment mFragment;
	KeyStore mKeyStore;
	KeyGenerator mKeyGenerator;
	Cipher mCipher;
	SharedPreferences mSharedPreferences;

	/**
	 * Constructor.
	 */
	public FingerprintAuth() {
	}

	/**
	 * Sets the context of the Command. This can then be used to do things like
	 * get file paths associated with the Activity.
	 *
	 * @param cordova
	 *            The context of the main Activity.
	 * @param webView
	 *            The CordovaWebView Cordova is running in.
	 */

	public void initialize(CordovaInterface cordova, CordovaWebView webView) {
		super.initialize(cordova, webView);
		Log.v(TAG, "Init FingerprintAuth");
		packageName = cordova.getActivity().getApplicationContext().getPackageName();
		mKeyguardManager = cordova.getActivity().getSystemService(KeyguardManager.class);
		mSharedPreferences = PreferenceManager.getDefaultSharedPreferences(cordova.getActivity());

		try {
			mKeyGenerator = KeyGenerator.getInstance(
					KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
			mKeyStore = KeyStore.getInstance("AndroidKeyStore");

		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
		} catch (KeyStoreException e) {
			throw new RuntimeException("Failed to get an instance of KeyStore", e);
		}

		try {
			mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
					+ KeyProperties.BLOCK_MODE_CBC + "/"
					+ KeyProperties.ENCRYPTION_PADDING_PKCS7);
		} catch (NoSuchAlgorithmException  e) {
			throw new RuntimeException("Failed to get an instance of Cipher", e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException("Failed to get an instance of Cipher", e);
		}
	}

	public boolean execute(final String action,
						   JSONArray args,
						   CallbackContext callbackContext) throws JSONException {
		Log.v(TAG, "FingerprintAuth action:" + action);
		createKey();

//		final int duration = Toast.LENGTH_SHORT;
//		JSONObject arg_object = args.getJSONObject(0);
//        final String message = arg_object.getString("message");
//		cordova.getActivity().runOnUiThread(new Runnable() {
//			public void run() {
//				Toast toast = Toast.makeText(
//						cordova.getActivity().getApplicationContext(), message, duration);
//				toast.show();
//			}
//		});

		cordova.getActivity().runOnUiThread(new Runnable() {
			public void run() {
				Log.d(TAG, "runOnUiThread");
				// Set up the crypto object for later. The object will be authenticated by use
				// of the fingerprint.
				if (initCipher()) {

					mFragment = new FingerprintAuthenticationDialogFragment();
					// Show the fingerprint dialog. The user has the option to use the fingerprint with
					// crypto, or you can fall back to using a server-side verified password.
					mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
					int use_fingerprint_to_authenticate_key_id = cordova.getActivity()
							.getResources().getIdentifier("use_fingerprint_to_authenticate_key",
									"string", FingerprintAuth.packageName);
					boolean useFingerprintPreference = mSharedPreferences
							.getBoolean(cordova.getActivity()
									.getString(use_fingerprint_to_authenticate_key_id), true);
					if (useFingerprintPreference) {
						mFragment.setStage(
								FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);
					} else {
						mFragment.setStage(
								FingerprintAuthenticationDialogFragment.Stage.PASSWORD);
					}
					mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
				} else {
					// This happens if the lock screen has been disabled or or a fingerprint got
					// enrolled. Thus show the dialog to authenticate with their password first
					// and ask the user if they want to authenticate with fingerprints in the
					// future
					mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
					mFragment.setStage(
							FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
					mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
				}
			}
		});
		return true;
	}

	/**
	 * Initialize the {@link Cipher} instance with the created key in the {@link #createKey()}
	 * method.
	 *
	 * @return {@code true} if initialization is successful, {@code false} if the lock screen has
	 * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
	 * the key was generated.
	 */
	private boolean initCipher() {
		Log.v(TAG, "initCipher()");
		try {
			mKeyStore.load(null);
			SecretKey key = (SecretKey) mKeyStore.getKey(KEY_NAME, null);
			mCipher.init(Cipher.ENCRYPT_MODE, key);
			return true;
		} catch (KeyPermanentlyInvalidatedException e) {
			return false;
		} catch (KeyStoreException e) {
			throw new RuntimeException("Failed to init Cipher", e);
		} catch (CertificateException e) {
			throw new RuntimeException("Failed to init Cipher", e);
		} catch (UnrecoverableKeyException e) {
			throw new RuntimeException("Failed to init Cipher", e);
		} catch (IOException e) {
			throw new RuntimeException("Failed to init Cipher", e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Failed to init Cipher", e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Failed to init Cipher", e);
		}
	}

	/**
	 * Creates a symmetric key in the Android Key Store which can only be used after the user has
	 * authenticated with fingerprint.
	 */
	public void createKey() {
		// The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
		// for your flow. Use of keys is necessary if you need to know if the set of
		// enrolled fingerprints has changed.
		try {
			mKeyStore.load(null);
			// Set the alias of the entry in Android KeyStore where the key will appear
			// and the constrains (purposes) in the constructor of the Builder
			mKeyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
					KeyProperties.PURPOSE_ENCRYPT |
							KeyProperties.PURPOSE_DECRYPT)
					.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
							// Require the user to authenticate with a fingerprint to authorize every use
							// of the key
					.setUserAuthenticationRequired(true)
					.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
					.build());
			mKeyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}