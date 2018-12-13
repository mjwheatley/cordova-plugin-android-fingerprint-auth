/*
 模仿 FingerprintAuthenticationDialogFragment 製作
 內容用的是 FingerprintManagerCompat
 注意實作方式 FingerprintManagerCompat.from( getContext()
 */

package com.cordova.plugin.android.fingerprintauth;

import android.annotation.TargetApi;
import android.app.DialogFragment;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * A dialog which uses fingerprint APIs to authenticate the user, and falls back to password
 * authentication if fingerprint is not available.
 */
@TargetApi(23)
public class FingerprintCompatAuthenticationDialogFragment extends DialogFragment
        implements FingerprintCompatUiHelper.Callback {

    private static final String TAG = "FingerprintAuthDialog";
    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;

    private Button mCancelButton;
    private Button mSecondDialogButton;
    private View mFingerprintContent;

    private Stage mStage = Stage.FINGERPRINT;

    private KeyguardManager mKeyguardManager;
    private FingerprintManagerCompat.CryptoObject mCryptoObject;
    private FingerprintCompatUiHelper mFingerprintUiHelper;
    FingerprintCompatUiHelper.FingerprintUiHelperBuilder mFingerprintUiHelperBuilder;

    public FingerprintCompatAuthenticationDialogFragment() {
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);
        setStyle(DialogFragment.STYLE_NO_TITLE, android.R.style.Theme_Material_Light_Dialog);

        mKeyguardManager = (KeyguardManager) getContext().getSystemService(Context.KEYGUARD_SERVICE);
        mFingerprintUiHelperBuilder = new FingerprintCompatUiHelper.FingerprintUiHelperBuilder(
                getContext(), FingerprintManagerCompat.from( getContext() ));

    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        Bundle args = getArguments();
        Log.d(TAG, "disableBackup: " + FingerprintAuth.mDisableBackup);

        // Inflate layout
        int fingerprint_dialog_container_id = getResources()
                .getIdentifier("fingerprint_dialog_container", "layout",
                        FingerprintAuth.packageName);
        View v = inflater.inflate(fingerprint_dialog_container_id, container, false);

        // Set dialog Title
        int fingerprint_auth_dialog_title_id = getResources()
                .getIdentifier("fingerprint_auth_dialog_title", "id", FingerprintAuth.packageName);
        TextView dialogTitleTextView = (TextView) v.findViewById(fingerprint_auth_dialog_title_id);
        if (null != FingerprintAuth.mDialogTitle) {
            dialogTitleTextView.setText(FingerprintAuth.mDialogTitle);
        }

        // Set dialog message
        int fingerprint_description_id = getResources()
                .getIdentifier("fingerprint_description", "id", FingerprintAuth.packageName);
        TextView dialogMessageTextView = (TextView) v.findViewById(fingerprint_description_id);
        if (null != FingerprintAuth.mDialogMessage) {
            dialogMessageTextView.setText(FingerprintAuth.mDialogMessage);
        }

        // Set dialog hing
        int fingerprint_hint_id = getResources()
                .getIdentifier("fingerprint_status", "id", FingerprintAuth.packageName);
        TextView dialogHintTextView = (TextView) v.findViewById(fingerprint_hint_id);
        if (null != FingerprintAuth.mDialogHint) {
            dialogHintTextView.setText(FingerprintAuth.mDialogHint);
        }

        int cancel_button_id = getResources()
                .getIdentifier("cancel_button", "id", FingerprintAuth.packageName);
        mCancelButton = (Button) v.findViewById(cancel_button_id);
        mCancelButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                FingerprintAuth.onCancelled();
                dismissAllowingStateLoss();
            }
        });

        int second_dialog_button_id = getResources()
                .getIdentifier("second_dialog_button", "id", FingerprintAuth.packageName);
        mSecondDialogButton = (Button) v.findViewById(second_dialog_button_id);
        if (FingerprintAuth.mDisableBackup) {
            mSecondDialogButton.setVisibility(View.GONE);
        }
        mSecondDialogButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                goToBackup();
            }
        });
        int fingerprint_container_id = getResources()
                .getIdentifier("fingerprint_container", "id", FingerprintAuth.packageName);
        mFingerprintContent = v.findViewById(fingerprint_container_id);

        int new_fingerprint_enrolled_description_id = getResources()
                .getIdentifier("new_fingerprint_enrolled_description", "id",
                        FingerprintAuth.packageName);

        int fingerprint_icon_id = getResources()
                .getIdentifier("fingerprint_icon", "id", FingerprintAuth.packageName);
        int fingerprint_status_id = getResources()
                .getIdentifier("fingerprint_status", "id", FingerprintAuth.packageName);
        mFingerprintUiHelper = mFingerprintUiHelperBuilder.build(
                (ImageView) v.findViewById(fingerprint_icon_id),
                (TextView) v.findViewById(fingerprint_status_id), this);
        updateStage();

        // If fingerprint authentication is not available, switch immediately to the backup
        // (password) screen.
        if (!mFingerprintUiHelper.isFingerprintAuthAvailable()) {
            goToBackup();
        }
        return v;
    }


    @Override
    public void onResume() {
        super.onResume();
        if (mStage == Stage.FINGERPRINT) {
            mFingerprintUiHelper.startListening(mCryptoObject);
        }
    }

    public void setStage(Stage stage) {
        mStage = stage;
    }

    @Override
    public void onPause() {
        super.onPause();
        mFingerprintUiHelper.stopListening();
    }

    /**
     * Sets the crypto object to be passed in when authenticating with fingerprint.
     */
    public void setCryptoObject(FingerprintManagerCompat.CryptoObject cryptoObject) {
        mCryptoObject = cryptoObject;
    }

    /**
     * Switches to backup (password) screen. This either can happen when fingerprint is not
     * available or the user chooses to use the password authentication method by pressing the
     * button. This can also happen when the user had too many fingerprint attempts.
     */
    private void goToBackup() {
        mStage = Stage.BACKUP;
        updateStage();
    }

    private void updateStage() {
        int cancel_id = getResources()
                .getIdentifier("cancel", "string", FingerprintAuth.packageName);
        switch (mStage) {
            case FINGERPRINT:
                mCancelButton.setText(cancel_id);
                int use_backup_id = getResources()
                        .getIdentifier("use_backup", "string", FingerprintAuth.packageName);
                mSecondDialogButton.setText(use_backup_id);
                mFingerprintContent.setVisibility(View.VISIBLE);
                break;
            case NEW_FINGERPRINT_ENROLLED:
                // Intentional fall through
            case BACKUP:
                if (mStage == Stage.NEW_FINGERPRINT_ENROLLED) {

                }
                if (!mKeyguardManager.isKeyguardSecure()) {
                    // Show a message that the user hasn't set up a lock screen.
                    int secure_lock_screen_required_id = getResources()
                            .getIdentifier("secure_lock_screen_required", "string",
                                    FingerprintAuth.packageName);
                    Toast.makeText(getContext(),
                            getString(secure_lock_screen_required_id),
                            Toast.LENGTH_LONG).show();
                    return;
                }
                if (FingerprintAuth.mDisableBackup) {
                    FingerprintAuth.onError("backup disabled");
                    return;
                }
                showAuthenticationScreen();
                break;
        }
    }

    private void showAuthenticationScreen() {
        // Create the Confirm Credentials screen. You can customize the title and description. Or
        // we will provide a generic one for you if you leave it null
        Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(null, null);
        if (intent != null) {
            startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            // Challenge completed, proceed with using cipher
            if (resultCode == getActivity().RESULT_OK) {
                FingerprintAuth.onAuthenticated(false /* used backup */, null);
            } else {
                // The user canceled or didn’t complete the lock screen
                // operation. Go to error/cancellation flow.
                FingerprintAuth.onCancelled();
            }
            dismissAllowingStateLoss();
        }
    }

    @Override
    public void onAuthenticated(FingerprintManagerCompat.AuthenticationResult result) {
        // Callback from FingerprintCompatUiHelper. Let the activity know that authentication was
        // successful.
        FingerprintAuth.onAuthenticatedForCompat(true /* withFingerprint */, result);
        dismissAllowingStateLoss();
    }

    @Override
    public void onError(CharSequence errString) {
        if (!FingerprintAuth.mDisableBackup) {
            if (getActivity() != null && isAdded()) {
                goToBackup();
            }
        } else {
            FingerprintAuth.onError(errString);
            dismissAllowingStateLoss();

        }
    }

    @Override
    public void onCancel(DialogInterface dialog) {
        super.onCancel(dialog);
        FingerprintAuth.onCancelled();
    }

    /**
     * Enumeration to indicate which authentication method the user is trying to authenticate with.
     */
    public enum Stage {
        FINGERPRINT,
        NEW_FINGERPRINT_ENROLLED,
        BACKUP
    }
}
