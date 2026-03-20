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

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class IntegrityModule extends ReactContextBaseJavaModule {

    static {
        System.loadLibrary("amoon_integrity");
    }

    // JNI declarations — nonce-bound, includes apkHash
    private native String computeAppSum(String certHashHex, String deviceId,
                                        String nonce, String apkHash);
    private native boolean isEnvironmentClean();

    private final ReactApplicationContext reactContext;

    public IntegrityModule(ReactApplicationContext context) {
        super(context);
        this.reactContext = context;
    }

    @NonNull
    @Override
    public String getName() { return "IntegrityModule"; }

    // ── Certificate hash ───────────────────────────────────────────────────────

    private String getSigningCertHash() {
        try {
            Context ctx = reactContext.getApplicationContext();
            PackageManager pm = ctx.getPackageManager();
            String pkg = ctx.getPackageName();

            Signature[] sigs;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
                sigs = pi.signingInfo.hasMultipleSigners()
                    ? pi.signingInfo.getApkContentsSigners()
                    : pi.signingInfo.getSigningCertificateHistory();
            } else {
                @SuppressWarnings("deprecation")
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                sigs = pi.signatures;
            }

            if (sigs == null || sigs.length == 0) return "";
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(sigs[0].toByteArray());
            return bytesToHex(md.digest());
        } catch (Exception e) {
            return "";
        }
    }

    // ── APK integrity hash (first 64 KB) ───────────────────────────────────────
    // Changes if the APK is modified/repackaged, unchanged for legitimate installs.

    private String getApkHash() {
        try {
            String apkPath = reactContext.getPackageCodePath();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            FileInputStream fis = new FileInputStream(apkPath);
            byte[] buf = new byte[65536]; // 64 KB — covers ZIP/DEX headers + cert
            int n = fis.read(buf);
            fis.close();
            if (n > 0) md.update(buf, 0, n);
            return bytesToHex(md.digest());
        } catch (Exception e) {
            return "unavailable";
        }
    }

    // ── Device ID ──────────────────────────────────────────────────────────────

    private String getDeviceId() {
        return Settings.Secure.getString(
            reactContext.getContentResolver(), Settings.Secure.ANDROID_ID);
    }

    // ── Java-level environment checks ──────────────────────────────────────────

    /** Detects Xposed Framework by probing for its bridge class. */
    private boolean isXposedActive() {
        try {
            ClassLoader.getSystemClassLoader()
                       .loadClass("de.robv.android.xposed.XposedBridge");
            return true; // class found → Xposed is loaded
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    /** Basic emulator detection via Build properties (complements C++ check). */
    private boolean isEmulatorBuild() {
        String fp = Build.FINGERPRINT;
        String model = Build.MODEL;
        return fp.startsWith("generic") || fp.startsWith("unknown") ||
               fp.contains("emulator") || fp.contains("sdk_gphone") ||
               model.contains("google_sdk") || model.contains("Emulator") ||
               model.contains("Android SDK built for") ||
               Build.MANUFACTURER.equals("Genymotion") ||
               Build.BRAND.startsWith("generic") ||
               Build.DEVICE.startsWith("generic") ||
               "google_sdk".equals(Build.PRODUCT);
    }

    /** Checks if Magisk Manager or common root manager apps are installed. */
    private boolean hasRootApp() {
        String[] rootApps = {
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
        };
        PackageManager pm = reactContext.getPackageManager();
        for (String pkg : rootApps) {
            try { pm.getApplicationInfo(pkg, 0); return true; }
            catch (PackageManager.NameNotFoundException ignored) {}
        }
        return false;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // ── React Native API ───────────────────────────────────────────────────────

    /**
     * getAppSum(nonce) — nonce-bound integrity token.
     * Formula: HMAC-SHA256(nonce:certHash:deviceId:apkHash, NATIVE_SALT)
     */
    @ReactMethod
    public void getAppSum(String nonce, Promise promise) {
        try {
            // Layer 1: C++ environment check (debug + root + emulator)
            if (!isEnvironmentClean()) {
                promise.reject("INTEGRITY_FAIL", "Compromised environment detected");
                return;
            }
            // Layer 2: Java-level checks (Xposed, root apps, emulator build)
            if (isXposedActive() || hasRootApp() || isEmulatorBuild()) {
                promise.reject("INTEGRITY_FAIL", "Hostile environment detected");
                return;
            }

            String certHash = getSigningCertHash();
            String deviceId = getDeviceId();
            String apkHash  = getApkHash();

            if (certHash.isEmpty() || deviceId == null || deviceId.isEmpty()) {
                promise.reject("INTEGRITY_FAIL", "Unable to retrieve device credentials");
                return;
            }

            String appSum = computeAppSum(certHash, deviceId, nonce, apkHash);
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
        boolean clean = isEnvironmentClean()
            && !isXposedActive()
            && !hasRootApp()
            && !isEmulatorBuild();
        promise.resolve(clean);
    }
}
