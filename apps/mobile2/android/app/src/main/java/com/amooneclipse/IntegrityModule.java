package com.amooneclipse;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * IntegrityModule
 *
 * React Native Native Module that exposes app-integrity verification to JS.
 *
 * JavaScript usage:
 *   import { NativeModules } from 'react-native';
 *   const { IntegrityModule } = NativeModules;
 *
 *   const nonce     = await IntegrityModule.getNonce();
 *   const signature = await IntegrityModule.computeRequestSignature(nonce, payloadJson);
 */
public class IntegrityModule extends ReactContextBaseJavaModule {

    private static final String TAG            = "AmoonIntegrity";
    private static final String MODULE_NAME    = "IntegrityModule";
    private static final String NATIVE_LIB     = "amoon_integrity";

    /**
     * Base URL for the AMoon Eclipse backend.
     * Override at build time via BuildConfig.API_BASE_URL or at runtime via
     * the EXPO_PUBLIC_API_URL environment variable (read by Metro/Expo).
     */
    private static final String DEFAULT_API_URL = "https://api.amoon.app";

    static {
        System.loadLibrary(NATIVE_LIB);
    }

    // -----------------------------------------------------------------------
    // Native method declarations (implemented in integrity_check.cpp)
    // -----------------------------------------------------------------------

    /**
     * Computes SHA-256 of the raw APK signing certificate DER bytes.
     *
     * @param certBytes raw bytes from {@link Signature#toByteArray()}
     * @return lower-case hex-encoded SHA-256 hash
     */
    private native String getAppSignatureHash(byte[] certBytes);

    /**
     * Computes HMAC-SHA256(nonce + ":" + payload, obfuscated_salt).
     *
     * @param nonce   the nonce obtained from the server
     * @param payload serialised request payload (JSON string)
     * @return lower-case hex-encoded HMAC
     */
    private native String computeHmac(String nonce, String payload);

    /**
     * Returns the deobfuscated salt (debug only — remove in production builds).
     */
    private native String getSalt();

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    public IntegrityModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @NonNull
    @Override
    public String getName() {
        return MODULE_NAME;
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /**
     * Returns the raw DER bytes of the first signing certificate in the
     * package, or {@code null} if the package cannot be found / has no sigs.
     */
    private byte[] getSigningCertBytes() {
        try {
            Context ctx = getReactApplicationContext();
            PackageManager pm = ctx.getPackageManager();
            String packageName = ctx.getPackageName();

            @SuppressWarnings("deprecation")
            PackageInfo info = pm.getPackageInfo(
                    packageName, PackageManager.GET_SIGNATURES);

            Signature[] sigs = info.signatures;
            if (sigs == null || sigs.length == 0) {
                Log.e(TAG, "No signatures found for package: " + packageName);
                return null;
            }

            // We use the first (and normally only) signing certificate.
            return sigs[0].toByteArray();

        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "Package not found: " + e.getMessage());
            return null;
        }
    }

    /**
     * Returns the current app signature hash as a hex string,
     * or an empty string on error.
     */
    private String getAppSignature() {
        byte[] certBytes = getSigningCertBytes();
        if (certBytes == null) {
            return "";
        }
        return getAppSignatureHash(certBytes);
    }

    /**
     * Resolves the API base URL.  Reads from BuildConfig if available,
     * falls back to the default.
     */
    private String getApiBaseUrl() {
        try {
            // BuildConfig.API_BASE_URL is injected via build.gradle:
            //   buildConfigField "String", "API_BASE_URL", "\"https://api.amoon.app\""
            return (String) Class
                    .forName(getReactApplicationContext().getPackageName() + ".BuildConfig")
                    .getField("API_BASE_URL")
                    .get(null);
        } catch (Exception ignored) {
            return DEFAULT_API_URL;
        }
    }

    // -----------------------------------------------------------------------
    // React Methods (exposed to JavaScript)
    // -----------------------------------------------------------------------

    /**
     * Issues a GET /api/auth/nonce request and resolves with the nonce string.
     *
     * Rejects the promise on network failure or non-200 response.
     */
    @ReactMethod
    public void getNonce(Promise promise) {
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                String apiUrl = getApiBaseUrl();
                URL url = new URL(apiUrl + "/api/auth/nonce");

                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(10_000);
                conn.setReadTimeout(10_000);
                conn.setRequestProperty("Accept", "application/json");

                int responseCode = conn.getResponseCode();
                if (responseCode != HttpURLConnection.HTTP_OK) {
                    promise.reject("NONCE_FETCH_FAILED",
                            "Server returned HTTP " + responseCode);
                    return;
                }

                StringBuilder sb = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(),
                                StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line);
                    }
                }

                String body = sb.toString().trim();

                // Support both plain-text nonce and JSON { "nonce": "..." }
                String nonce;
                if (body.startsWith("{")) {
                    JSONObject json = new JSONObject(body);
                    nonce = json.getString("nonce");
                } else {
                    nonce = body;
                }

                if (nonce == null || nonce.isEmpty()) {
                    promise.reject("NONCE_EMPTY", "Server returned empty nonce");
                    return;
                }

                promise.resolve(nonce);

            } catch (Exception e) {
                Log.e(TAG, "getNonce error: " + e.getMessage(), e);
                promise.reject("NONCE_ERROR", e.getMessage(), e);
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }).start();
    }

    /**
     * Computes the request signature for a given nonce and payload.
     *
     * The signature is HMAC-SHA256(nonce + ":" + payloadJson, secret_salt)
     * computed in native C++ code so it is not visible in the Hermes bytecode.
     *
     * @param nonce       the nonce string returned by {@link #getNonce}
     * @param payloadJson JSON string of the request body (use "{}" for GET)
     * @param promise     resolves with the hex HMAC string
     */
    @ReactMethod
    public void computeRequestSignature(String nonce, String payloadJson, Promise promise) {
        try {
            if (nonce == null || nonce.isEmpty()) {
                promise.reject("INVALID_NONCE", "Nonce must not be empty");
                return;
            }
            if (payloadJson == null) {
                payloadJson = "{}";
            }

            String hmac = computeHmac(nonce, payloadJson);
            if (hmac == null || hmac.isEmpty()) {
                promise.reject("HMAC_FAILED", "Native HMAC computation returned empty result");
                return;
            }

            promise.resolve(hmac);

        } catch (Exception e) {
            Log.e(TAG, "computeRequestSignature error: " + e.getMessage(), e);
            promise.reject("HMAC_ERROR", e.getMessage(), e);
        }
    }

    /**
     * Returns the current app signature hash.
     * Exposed for JS so the secureRequest helper can attach it to headers.
     *
     * @param promise resolves with the hex SHA-256 app hash
     */
    @ReactMethod
    public void getAppSignatureHash(Promise promise) {
        try {
            String hash = getAppSignature();
            promise.resolve(hash);
        } catch (Exception e) {
            Log.e(TAG, "getAppSignatureHash error: " + e.getMessage(), e);
            promise.reject("HASH_ERROR", e.getMessage(), e);
        }
    }
}
