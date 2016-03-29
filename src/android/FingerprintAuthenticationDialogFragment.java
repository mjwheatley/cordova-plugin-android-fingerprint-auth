/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.cordova.plugin.android.fingerprintauth;

import android.app.Activity;
import android.app.DialogFragment;
import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;

import com.cordova.plugin.android.fingerprintauth.FingerprintUiHelper;

/**
 * A dialog which uses fingerprint APIs to authenticate the user, and falls back to password
 * authentication if fingerprint is not available.
 */
public class FingerprintAuthenticationDialogFragment extends DialogFragment
        implements TextView.OnEditorActionListener, FingerprintUiHelper.Callback {

    private Button mCancelButton;
    private Button mSecondDialogButton;
    private View mFingerprintContent;
    private View mBackupContent;
    private EditText mPassword;
    private CheckBox mUseFingerprintFutureCheckBox;
    private TextView mPasswordDescriptionTextView;
    private TextView mNewFingerprintEnrolledTextView;

    private Stage mStage = Stage.FINGERPRINT;

    private FingerprintManager.CryptoObject mCryptoObject;
    private FingerprintUiHelper mFingerprintUiHelper;
//    private MainActivity mActivity;

    FingerprintUiHelper.FingerprintUiHelperBuilder mFingerprintUiHelperBuilder;
    InputMethodManager mInputMethodManager;
    SharedPreferences mSharedPreferences;

    public FingerprintAuthenticationDialogFragment() {
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);
        setStyle(DialogFragment.STYLE_NORMAL, android.R.style.Theme_Material_Light_Dialog);

        mFingerprintUiHelperBuilder = new FingerprintUiHelper.FingerprintUiHelperBuilder(
                getContext(), getContext().getSystemService(FingerprintManager.class));

        mInputMethodManager = (InputMethodManager) getContext()
                .getSystemService(Context.INPUT_METHOD_SERVICE);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        int sign_in_id = getResources()
                .getIdentifier("sign_in", "string", FingerprintAuth.packageName);
        getDialog().setTitle(getString(sign_in_id));
        int fingerprint_dialog_container_id = getResources()
                .getIdentifier("fingerprint_dialog_container", "layout",
                        FingerprintAuth.packageName);
        View v = inflater.inflate(fingerprint_dialog_container_id, container, false);
        int cancel_button_id = getResources()
                .getIdentifier("cancel_button", "id", FingerprintAuth.packageName);
        mCancelButton = (Button) v.findViewById(cancel_button_id);
        mCancelButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                dismiss();
            }
        });

        int second_dialog_button_id = getResources()
                .getIdentifier("second_dialog_button", "id", FingerprintAuth.packageName);
        mSecondDialogButton = (Button) v.findViewById(second_dialog_button_id);
        mSecondDialogButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (mStage == Stage.FINGERPRINT) {
                    goToBackup();
                } else {
                    verifyPassword();
                }
            }
        });
        int fingerprint_container_id = getResources()
                .getIdentifier("fingerprint_container", "id", FingerprintAuth.packageName);
        mFingerprintContent = v.findViewById(fingerprint_container_id);
        int backup_container_id = getResources()
                .getIdentifier("backup_container", "id", FingerprintAuth.packageName);
        mBackupContent = v.findViewById(backup_container_id);
        int password_id = getResources()
                .getIdentifier("password", "id", FingerprintAuth.packageName);
        mPassword = (EditText) v.findViewById(password_id);
        mPassword.setOnEditorActionListener(this);
        int password_description_id = getResources()
                .getIdentifier("password_description", "id", FingerprintAuth.packageName);
        mPasswordDescriptionTextView = (TextView) v.findViewById(password_description_id);

        int use_fingerprint_in_future_check_id = getResources()
                .getIdentifier("use_fingerprint_in_future_check", "id",
                        FingerprintAuth.packageName);
        mUseFingerprintFutureCheckBox = (CheckBox)
                v.findViewById(use_fingerprint_in_future_check_id);

        int new_fingerprint_enrolled_description_id = getResources()
                .getIdentifier("new_fingerprint_enrolled_description", "id",
                        FingerprintAuth.packageName);
        mNewFingerprintEnrolledTextView = (TextView)
                v.findViewById(new_fingerprint_enrolled_description_id);

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

    @Override
    public void onAttach(Activity activity) {
        super.onAttach(activity);
//        mActivity = (MainActivity) activity;
    }

    /**
     * Sets the crypto object to be passed in when authenticating with fingerprint.
     */
    public void setCryptoObject(FingerprintManager.CryptoObject cryptoObject) {
        mCryptoObject = cryptoObject;
    }

    /**
     * Switches to backup (password) screen. This either can happen when fingerprint is not
     * available or the user chooses to use the password authentication method by pressing the
     * button. This can also happen when the user had too many fingerprint attempts.
     */
    private void goToBackup() {
        mStage = Stage.PASSWORD;
        updateStage();
        mPassword.requestFocus();

        // Show the keyboard.
        mPassword.postDelayed(mShowKeyboardRunnable, 500);

        // Fingerprint is not used anymore. Stop listening for it.
        mFingerprintUiHelper.stopListening();
    }

    /**
     * Checks whether the current entered password is correct, and dismisses the the dialog and
     * let's the activity know about the result.
     */
    private void verifyPassword() {
        if (!checkPassword(mPassword.getText().toString())) {
            return;
        }
        if (mStage == Stage.NEW_FINGERPRINT_ENROLLED) {
            SharedPreferences.Editor editor = mSharedPreferences.edit();

            int use_fingerprint_to_authenticate_key_id = getResources()
                    .getIdentifier("use_fingerprint_to_authenticate_key", "string",
                            FingerprintAuth.packageName);
            editor.putBoolean(getString(use_fingerprint_to_authenticate_key_id),
                    mUseFingerprintFutureCheckBox.isChecked());
            editor.apply();

            if (mUseFingerprintFutureCheckBox.isChecked()) {
                // Re-create the key so that fingerprints including new ones are validated.
//                mActivity.createKey();
                mStage = Stage.FINGERPRINT;
            }
        }
        mPassword.setText("");
//        mActivity.onPurchased(false /* without Fingerprint */);
        dismiss();
    }

    /**
     * @return true if {@code password} is correct, false otherwise
     */
    private boolean checkPassword(String password) {
        // Assume the password is always correct.
        // In the real world situation, the password needs to be verified in the server side.
        return password.length() > 0;
    }

    private final Runnable mShowKeyboardRunnable = new Runnable() {
        @Override
        public void run() {
            mInputMethodManager.showSoftInput(mPassword, 0);
        }
    };

    private void updateStage() {
        int cancel_id = getResources()
                .getIdentifier("cancel", "string", FingerprintAuth.packageName);
        switch (mStage) {
            case FINGERPRINT:
                mCancelButton.setText(cancel_id);
                int use_password_id = getResources()
                        .getIdentifier("use_password", "string", FingerprintAuth.packageName);
                mSecondDialogButton.setText(use_password_id);
                mFingerprintContent.setVisibility(View.VISIBLE);
                mBackupContent.setVisibility(View.GONE);
                break;
            case NEW_FINGERPRINT_ENROLLED:
                // Intentional fall through
            case PASSWORD:
                mCancelButton.setText(cancel_id);
                int ok_id = getResources()
                        .getIdentifier("ok", "string", FingerprintAuth.packageName);
                mSecondDialogButton.setText(ok_id);
                mFingerprintContent.setVisibility(View.GONE);
                mBackupContent.setVisibility(View.VISIBLE);
                if (mStage == Stage.NEW_FINGERPRINT_ENROLLED) {
                    mPasswordDescriptionTextView.setVisibility(View.GONE);
                    mNewFingerprintEnrolledTextView.setVisibility(View.VISIBLE);
                    mUseFingerprintFutureCheckBox.setVisibility(View.VISIBLE);
                }
                break;
        }
    }

    @Override
    public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
        if (actionId == EditorInfo.IME_ACTION_GO) {
            verifyPassword();
            return true;
        }
        return false;
    }

    @Override
    public void onAuthenticated() {
        // Callback from FingerprintUiHelper. Let the activity know that authentication was
        // successful.
//        mActivity.onPurchased(true /* withFingerprint */);
        dismiss();
    }

    @Override
    public void onError() {
        goToBackup();
    }

    /**
     * Enumeration to indicate which authentication method the user is trying to authenticate with.
     */
    public enum Stage {
        FINGERPRINT,
        NEW_FINGERPRINT_ENROLLED,
        PASSWORD
    }
}
