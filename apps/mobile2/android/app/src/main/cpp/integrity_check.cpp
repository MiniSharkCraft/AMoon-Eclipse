/**
 * integrity_check.cpp
 * AMoon Eclipse — Native integrity verification layer.
 *
 * Provides JNI functions called by IntegrityModule.java:
 *   - getAppSignatureHash   : SHA-256 of the APK signing certificate bytes
 *   - computeHmac           : HMAC-SHA256(nonce ":" payload, obfuscated_salt)
 *   - getSalt               : returns the obfuscated salt (for debug/testing only)
 *
 * The secret salt is split into 4 segments and each XOR-masked with a
 * different key so that it never appears in plaintext in the binary.
 * Volatile local variables prevent the compiler from optimising away
 * the deobfuscation steps.
 *
 * Build with NDK r23+ and OpenSSL (see CMakeLists.txt).
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <vector>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <android/log.h>

#define LOG_TAG "AmoonIntegrity"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Helper: convert raw bytes to lower-case hex string
// ---------------------------------------------------------------------------
static std::string bytesToHex(const unsigned char *data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(hex_chars[(data[i] >> 4) & 0x0F]);
        result.push_back(hex_chars[data[i] & 0x0F]);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Salt deobfuscation
//
// Original salt: "AMOON_ECLIPSE_INTEGRITY_2025"
// Split into 4 segments (7 / 7 / 9 / 4 chars):
//   seg0 = "AMOON_E"  XOR key0 (0x13)
//   seg1 = "CLIPSE_"  XOR key1 (0x27)
//   seg2 = "INTEGRIT"  XOR key2 (0x5A)   (8 chars to align nicely)
//   seg3 = "Y_2025"   XOR key3 (0x3F)
//
// Pre-computed masked bytes are stored as static arrays.
// At runtime, XOR each byte with its key and concatenate.
// ---------------------------------------------------------------------------

// seg0 = "AMOON_E" ^ 0x13
static const volatile unsigned char kSeg0Masked[] = {
    'A' ^ 0x13, 'M' ^ 0x13, 'O' ^ 0x13, 'O' ^ 0x13,
    'N' ^ 0x13, '_' ^ 0x13, 'E' ^ 0x13
};
static const size_t kSeg0Len = 7;
static const unsigned char kKey0 = 0x13;

// seg1 = "CLIPSE_" ^ 0x27
static const volatile unsigned char kSeg1Masked[] = {
    'C' ^ 0x27, 'L' ^ 0x27, 'I' ^ 0x27, 'P' ^ 0x27,
    'S' ^ 0x27, 'E' ^ 0x27, '_' ^ 0x27
};
static const size_t kSeg1Len = 7;
static const unsigned char kKey1 = 0x27;

// seg2 = "INTEGRIT" ^ 0x5A  (8 chars)
static const volatile unsigned char kSeg2Masked[] = {
    'I' ^ 0x5A, 'N' ^ 0x5A, 'T' ^ 0x5A, 'E' ^ 0x5A,
    'G' ^ 0x5A, 'R' ^ 0x5A, 'I' ^ 0x5A, 'T' ^ 0x5A
};
static const size_t kSeg2Len = 8;
static const unsigned char kKey2 = 0x5A;

// seg3 = "Y_2025" ^ 0x3F  (6 chars)
static const volatile unsigned char kSeg3Masked[] = {
    'Y' ^ 0x3F, '_' ^ 0x3F, '2' ^ 0x3F, '0' ^ 0x3F,
    '2' ^ 0x3F, '5' ^ 0x3F
};
static const size_t kSeg3Len = 6;
static const unsigned char kKey3 = 0x3F;

/**
 * Deobfuscate and return the salt string.
 * Uses volatile intermediates to prevent dead-code elimination.
 */
static std::string deobfuscateSalt() {
    // Total length: 7 + 7 + 8 + 6 = 28
    std::string salt;
    salt.reserve(kSeg0Len + kSeg1Len + kSeg2Len + kSeg3Len);

    // Segment 0
    for (size_t i = 0; i < kSeg0Len; ++i) {
        volatile unsigned char masked = kSeg0Masked[i];
        volatile unsigned char plain  = masked ^ kKey0;
        salt.push_back(static_cast<char>(plain));
    }
    // Segment 1
    for (size_t i = 0; i < kSeg1Len; ++i) {
        volatile unsigned char masked = kSeg1Masked[i];
        volatile unsigned char plain  = masked ^ kKey1;
        salt.push_back(static_cast<char>(plain));
    }
    // Segment 2
    for (size_t i = 0; i < kSeg2Len; ++i) {
        volatile unsigned char masked = kSeg2Masked[i];
        volatile unsigned char plain  = masked ^ kKey2;
        salt.push_back(static_cast<char>(plain));
    }
    // Segment 3
    for (size_t i = 0; i < kSeg3Len; ++i) {
        volatile unsigned char masked = kSeg3Masked[i];
        volatile unsigned char plain  = masked ^ kKey3;
        salt.push_back(static_cast<char>(plain));
    }

    return salt;
}

// ---------------------------------------------------------------------------
// JNI: getAppSignatureHash
//
// Accepts the raw signing certificate bytes from Java, computes SHA-256,
// and returns a lower-case hex string.
// ---------------------------------------------------------------------------
extern "C"
JNIEXPORT jstring JNICALL
Java_com_amooneclipse_IntegrityModule_getAppSignatureHash(
        JNIEnv *env,
        jobject /* thiz */,
        jbyteArray certBytes) {

    if (certBytes == nullptr) {
        LOGE("getAppSignatureHash: certBytes is null");
        return env->NewStringUTF("");
    }

    jsize len = env->GetArrayLength(certBytes);
    if (len <= 0) {
        LOGE("getAppSignatureHash: certBytes is empty");
        return env->NewStringUTF("");
    }

    jbyte *bytes = env->GetByteArrayElements(certBytes, nullptr);
    if (bytes == nullptr) {
        LOGE("getAppSignatureHash: failed to pin byte array");
        return env->NewStringUTF("");
    }

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(bytes), static_cast<size_t>(len), digest);

    env->ReleaseByteArrayElements(certBytes, bytes, JNI_ABORT);

    std::string hexHash = bytesToHex(digest, SHA256_DIGEST_LENGTH);
    LOGI("App signature hash computed: %.16s...", hexHash.c_str());

    return env->NewStringUTF(hexHash.c_str());
}

// ---------------------------------------------------------------------------
// JNI: computeHmac
//
// Computes HMAC-SHA256( nonce + ":" + payload, salt ) and returns the
// lower-case hex string.  The salt is deobfuscated at call time.
// ---------------------------------------------------------------------------
extern "C"
JNIEXPORT jstring JNICALL
Java_com_amooneclipse_IntegrityModule_computeHmac(
        JNIEnv *env,
        jobject /* thiz */,
        jstring jNonce,
        jstring jPayload) {

    if (jNonce == nullptr || jPayload == nullptr) {
        LOGE("computeHmac: null argument(s)");
        return env->NewStringUTF("");
    }

    // Get Java strings as UTF-8 C strings
    const char *nonce   = env->GetStringUTFChars(jNonce,   nullptr);
    const char *payload = env->GetStringUTFChars(jPayload, nullptr);

    if (nonce == nullptr || payload == nullptr) {
        if (nonce)   env->ReleaseStringUTFChars(jNonce,   nonce);
        if (payload) env->ReleaseStringUTFChars(jPayload, payload);
        LOGE("computeHmac: failed to get string chars");
        return env->NewStringUTF("");
    }

    // Build message: nonce + ":" + payload
    std::string message(nonce);
    message.push_back(':');
    message.append(payload);

    env->ReleaseStringUTFChars(jNonce,   nonce);
    env->ReleaseStringUTFChars(jPayload, payload);

    // Deobfuscate salt
    std::string salt = deobfuscateSalt();

    // Compute HMAC-SHA256
    unsigned char hmacResult[EVP_MAX_MD_SIZE];
    unsigned int  hmacLen = 0;

    const unsigned char *keyPtr =
            reinterpret_cast<const unsigned char *>(salt.data());
    const unsigned char *msgPtr =
            reinterpret_cast<const unsigned char *>(message.data());

    unsigned char *result = HMAC(
            EVP_sha256(),
            keyPtr, static_cast<int>(salt.size()),
            msgPtr, static_cast<int>(message.size()),
            hmacResult, &hmacLen);

    if (result == nullptr || hmacLen == 0) {
        LOGE("computeHmac: HMAC computation failed");
        return env->NewStringUTF("");
    }

    std::string hexHmac = bytesToHex(hmacResult, hmacLen);
    return env->NewStringUTF(hexHmac.c_str());
}

// ---------------------------------------------------------------------------
// JNI: getSalt
//
// Returns the deobfuscated salt as a Java String.
// THIS FUNCTION IS INTENTIONALLY LEFT FOR DEBUG/TEST ONLY.
// Remove or gate behind BuildConfig.DEBUG before production release.
// ---------------------------------------------------------------------------
extern "C"
JNIEXPORT jstring JNICALL
Java_com_amooneclipse_IntegrityModule_getSalt(
        JNIEnv *env,
        jobject /* thiz */) {
    std::string salt = deobfuscateSalt();
    return env->NewStringUTF(salt.c_str());
}
