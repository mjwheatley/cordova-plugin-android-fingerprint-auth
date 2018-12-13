/*
 模仿 FingerprintUiHelper 製作
 內容用的是 FingerprintManagerCompat
 注意實作方式 FingerprintManagerCompat.from( getContext()
 */
package com.cordova.plugin.android.fingerprintauth;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v4.os.CancellationSignal;
import android.widget.ImageView;
import android.widget.TextView;

@TargetApi(23)
public class FingerprintCompatUiHelper extends FingerprintManagerCompat.AuthenticationCallback {

    static final long ERROR_TIMEOUT_MILLIS = 1600;
    static final long SUCCESS_DELAY_MILLIS = 1300;

    private final Context mContext;
    private final FingerprintManagerCompat mFingerprintManager;
    private final ImageView mIcon;
    private final TextView mErrorTextView;
    private final Callback mCallback;
    private CancellationSignal mCancellationSignal;
    private int mAttempts = 0;
    private static FingerprintManagerCompat.AuthenticationResult fingerprintResult;

    boolean mSelfCancelled;
    /**
     * Builder class for {@link FingerprintCompatUiHelper} in which injected fields from Dagger
     * holds its fields and takes other arguments in the {@link #build} method.
     */
    public static class FingerprintUiHelperBuilder {
        private final FingerprintManagerCompat mFingerPrintManager;
        private final Context mContext;

        public FingerprintUiHelperBuilder(Context context, FingerprintManagerCompat fingerprintManager) {
            mFingerPrintManager = fingerprintManager;
            mContext = context;
        }

        public FingerprintCompatUiHelper build(ImageView icon, TextView errorTextView, Callback callback) {
            return new FingerprintCompatUiHelper(mContext, mFingerPrintManager, icon, errorTextView,
                    callback);
        }
    }

    /**
     * Constructor for {@link FingerprintUiHelper}. This method is expected to be called from
     * only the {@link FingerprintUiHelperBuilder} class.
     */
    private FingerprintCompatUiHelper(Context context, FingerprintManagerCompat fingerprintManager,
                                ImageView icon, TextView errorTextView, Callback callback) {
        mFingerprintManager = fingerprintManager;
        mIcon = icon;
        mErrorTextView = errorTextView;
        mCallback = callback;
        mContext = context;
    }

    public boolean isFingerprintAuthAvailable() {
        return mFingerprintManager.isHardwareDetected()
                && mFingerprintManager.hasEnrolledFingerprints();
    }

    public void startListening(FingerprintManagerCompat.CryptoObject cryptoObject) {
        if (!isFingerprintAuthAvailable()) {
            return;
        }
        mCancellationSignal = new CancellationSignal();
        mSelfCancelled = false;
        mFingerprintManager
                .authenticate(cryptoObject,0, mCancellationSignal, this, null);

        int ic_fp_40px_id = mContext.getResources()
                .getIdentifier("ic_fp_40px", "drawable", FingerprintAuth.packageName);
        mIcon.setImageResource(ic_fp_40px_id);
    }

    public void stopListening() {
        if (mCancellationSignal != null) {
            mSelfCancelled = true;
            mCancellationSignal.cancel();
            mCancellationSignal = null;
        }
    }

    @Override
    public void onAuthenticationError(int errMsgId, CharSequence errString) {
        if (!mSelfCancelled) {
            showError(errString);
            mIcon.postDelayed(new Runnable() {
                @Override
                public void run() {
                    mCallback.onError(errString);
                }
            }, ERROR_TIMEOUT_MILLIS);
        }
    }

    @Override
    public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
        showError(helpString);
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
        fingerprintResult = result;
        mErrorTextView.removeCallbacks(mResetErrorTextRunnable);
        int ic_fingerprint_success_id = mContext.getResources()
                .getIdentifier("ic_fingerprint_success", "drawable", FingerprintAuth.packageName);
        mIcon.setImageResource(ic_fingerprint_success_id);
        int success_color_id = mContext.getResources()
                .getIdentifier("success_color", "color", FingerprintAuth.packageName);
        mErrorTextView.setTextColor(
                mErrorTextView.getResources().getColor(success_color_id, null));
        int fingerprint_success_id = mContext.getResources()
                .getIdentifier("fingerprint_success", "string", FingerprintAuth.packageName);
        mErrorTextView.setText(
                mErrorTextView.getResources().getString(fingerprint_success_id));
        mIcon.postDelayed(new Runnable() {
            @Override
            public void run() {
                mCallback.onAuthenticated(fingerprintResult);
            }
        }, SUCCESS_DELAY_MILLIS);
    }

    @Override
    public void onAuthenticationFailed() {
        mAttempts++;
        int fingerprint_not_recognized_id = mContext.getResources()
                .getIdentifier("fingerprint_not_recognized", "string",
                        FingerprintAuth.packageName);
        int fingerprint_too_many_attempts_id = mContext.getResources()
                .getIdentifier("fingerprint_too_many_attempts", "string",
                        FingerprintAuth.packageName);
        final String too_many_attempts_string = mIcon.getResources().getString(
                fingerprint_too_many_attempts_id);
        if (mAttempts > FingerprintAuth.mMaxAttempts) {
            showError(too_many_attempts_string);
            mIcon.postDelayed(new Runnable() {
                @Override
                public void run() {
                    mCallback.onError(too_many_attempts_string);
                }
            }, ERROR_TIMEOUT_MILLIS);
        } else {
            showError(mIcon.getResources().getString(
                    fingerprint_not_recognized_id));
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void showError(CharSequence error) {
        int ic_fingerprint_error_id = mContext.getResources()
                .getIdentifier("ic_fingerprint_error", "drawable", FingerprintAuth.packageName);
        mIcon.setImageResource(ic_fingerprint_error_id);
        mErrorTextView.setText(error);
        int warning_color_id = mContext.getResources()
                .getIdentifier("warning_color", "color", FingerprintAuth.packageName);
        mErrorTextView.setTextColor(
                mErrorTextView.getResources().getColor(warning_color_id, null));
        mErrorTextView.removeCallbacks(mResetErrorTextRunnable);
        mErrorTextView.postDelayed(mResetErrorTextRunnable, ERROR_TIMEOUT_MILLIS);
    }

    Runnable mResetErrorTextRunnable = new Runnable() {
        @Override
        public void run() {
            int hint_color_id = mContext.getResources()
                    .getIdentifier("hint_color", "color", FingerprintAuth.packageName);
            mErrorTextView.setTextColor(
                    mErrorTextView.getResources().getColor(hint_color_id, null));
            int fingerprint_hint_id = mContext.getResources()
                    .getIdentifier("fingerprint_hint", "string", FingerprintAuth.packageName);
            mErrorTextView.setText(
                    mErrorTextView.getResources().getString(fingerprint_hint_id));
            int ic_fp_40px_id = mContext.getResources()
                    .getIdentifier("ic_fp_40px", "drawable", FingerprintAuth.packageName);
            mIcon.setImageResource(ic_fp_40px_id);
        }
    };

    public interface Callback {

        void onAuthenticated(FingerprintManagerCompat.AuthenticationResult result);

        void onError(CharSequence errString);
    }
}
