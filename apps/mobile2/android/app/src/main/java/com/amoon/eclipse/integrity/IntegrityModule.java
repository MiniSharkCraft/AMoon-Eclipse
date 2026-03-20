package com.amoon.eclipse.integrity;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.provider.Settings;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class IntegrityModule extends ReactContextBaseJavaModule {

    static {
        System.loadLibrary("amoon_integrity");
    }

    // JNI declarations
    private native String computeAppSum(String certHashHex, String deviceId);
    private native boolean isEnvironmentClean();

    private final ReactApplicationContext reactContext;

    public IntegrityModule(ReactApplicationContext context) {
        super(context);
        this.reactContext = context;
    }

    @NonNull
    @Override
    public String getName() {
        return "IntegrityModule";
    }

    /**
     * Get the SHA-256 fingerprint of the APK signing certificate.
     */
    private String getSigningCertHash() {
        try {
            Context ctx = reactContext.getApplicationContext();
            PackageManager pm = ctx.getPackageManager();
            String pkg = ctx.getPackageName();

            Signature[] sigs;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
                if (pi.signingInfo.hasMultipleSigners()) {
                    sigs = pi.signingInfo.getApkContentsSigners();
                } else {
                    sigs = pi.signingInfo.getSigningCertificateHistory();
                }
            } else {
                @SuppressWarnings("deprecation")
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                sigs = pi.signatures;
            }

            if (sigs == null || sigs.length == 0) return "";

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(sigs[0].toByteArray());
            return bytesToHex(md.digest());

        } catch (PackageManager.NameNotFoundException | NoSuchAlgorithmException e) {
            return "";
        }
    }

    /**
     * Get a stable device identifier (Android ID).
     * Note: resets on factory reset, unique per app+device.
     */
    private String getDeviceId() {
        return Settings.Secure.getString(
            reactContext.getContentResolver(),
            Settings.Secure.ANDROID_ID
        );
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // ── React Native API ───────────────────────────────────────────────────────

    @ReactMethod
    public void getAppSum(Promise promise) {
        try {
            if (!isEnvironmentClean()) {
                promise.reject("INTEGRITY_FAIL", "Compromised environment detected");
                return;
            }

            String certHash = getSigningCertHash();
            String deviceId = getDeviceId();

            if (certHash.isEmpty() || deviceId == null || deviceId.isEmpty()) {
                promise.reject("INTEGRITY_FAIL", "Unable to retrieve device credentials");
                return;
            }

            String appSum = computeAppSum(certHash, deviceId);
            if (appSum.isEmpty()) {
                promise.reject("INTEGRITY_FAIL", "HMAC computation failed");
                return;
            }

            promise.resolve(appSum);
        } catch (Exception e) {
            promise.reject("INTEGRITY_ERROR", e.getMessage());
        }
    }

    @ReactMethod
    public void checkEnvironment(Promise promise) {
        promise.resolve(isEnvironmentClean());
    }
}
