/**
 * AMoon Eclipse — Runtime Integrity Check (iOS)
 *
 * Computes App-Integrity-Sum using:
 *   - Signing team ID from embedded provisioning profile
 *   - Device identifier (identifierForVendor)
 *   - Request nonce (nonce-bound — cannot be replayed)
 *   - App binary hash (detects tampered IPA)
 *   - SECRET_SALT masked in binary (same XOR scheme as Android)
 */

#import <React/RCTBridgeModule.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdint>

// ─── Same masked salt as Android ─────────────────────────────────────────────

static constexpr uint8_t MASK_A = 0xA7;
static constexpr uint8_t MASK_B = 0x3F;

static inline uint8_t keyAt(size_t i) {
    return static_cast<uint8_t>(MASK_A ^ ((i * MASK_B) & 0xFF));
}

static const uint8_t MASKED_SALT[] = {
    0xC6,0xCF,0xCB,0xCA,0xCB,0xA5,0xCC,0x5A,
    0xC0,0x6B,0xC1,0x68,0xC3,0x6B,0xC6,0x77,
    0xD3,0x5C,0xD5,0x56,0xCB,0x48,0xC3,0x44,
    0xC9,0x42,0xCD,0x60,0xC5,0x73,0xCB,0x00
};
static constexpr size_t SALT_LEN = sizeof(MASKED_SALT);

static void unmaskSalt(uint8_t* out) {
    for (size_t i = 0; i < SALT_LEN; i++) {
        out[i] = MASKED_SALT[i] ^ keyAt(i);
    }
}

// ─── Anti-debug (iOS) ────────────────────────────────────────────────────────

static bool isBeingDebugged() {
    // sysctl P_TRACED flag
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)getpid() };
    struct kinfo_proc info = {};
    size_t size = sizeof(info);
    sysctl(mib, 4, &info, &size, nullptr, 0);
    if (info.kp_proc.p_flag & P_TRACED) return true;

    // Suspicious Frida / Cycript dylibs in memory
    const char* fridaLibs[] = {
        "FridaGadget", "frida", "cynject", "libcycript", nullptr
    };
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        if (!name) continue;
        for (int j = 0; fridaLibs[j]; j++) {
            if (strstr(name, fridaLibs[j])) return true;
        }
    }

    return false;
}

// ─── Jailbreak detection ─────────────────────────────────────────────────────

static bool isJailbroken() {
    // 1. Known jailbreak file system artifacts
    static const char* jbPaths[] = {
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/etc/apt",
        "/var/lib/dpkg",
        "/private/var/lib/apt",
        "/private/var/mobile/Library/SBSettings",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        nullptr
    };
    for (int i = 0; jbPaths[i]; i++) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:
             [NSString stringWithUTF8String:jbPaths[i]]]) return true;
    }

    // 2. Sandbox escape check: can we write outside sandbox?
    NSError* err = nil;
    [@"jb" writeToFile:@"/private/jb_probe.txt"
            atomically:NO encoding:NSUTF8StringEncoding error:&err];
    if (!err) {
        // Write succeeded — sandbox is broken
        [[NSFileManager defaultManager] removeItemAtPath:@"/private/jb_probe.txt" error:nil];
        return true;
    }

    // 3. Substrate / Substitute / ElleKit in dyld image list
    const char* substrateLibs[] = {
        "MobileSubstrate", "CydiaSubstrate", "substitute", "ElleKit", nullptr
    };
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        if (!name) continue;
        for (int j = 0; substrateLibs[j]; j++) {
            if (strstr(name, substrateLibs[j])) return true;
        }
    }

    return false;
}

// ─── Signing info ─────────────────────────────────────────────────────────────

static NSString* getSigningTeamId() {
    NSString* profilePath = [NSBundle.mainBundle pathForResource:@"embedded"
                                                          ofType:@"mobileprovision"];
    if (profilePath) {
        NSData* data = [NSData dataWithContentsOfFile:profilePath];
        if (data) {
            NSString* raw = [[NSString alloc] initWithData:data
                                                  encoding:NSISOLatin1StringEncoding];
            NSRange start = [raw rangeOfString:@"<key>TeamIdentifier</key>"];
            if (start.location != NSNotFound) {
                NSRange search = NSMakeRange(start.location, MIN(300UL, raw.length - start.location));
                NSRange val = [raw rangeOfString:@"<string>" options:0 range:search];
                NSRange end = [raw rangeOfString:@"</string>" options:0
                                           range:NSMakeRange(val.location, 200)];
                if (val.location != NSNotFound && end.location != NSNotFound) {
                    NSRange tid = NSMakeRange(val.location + 8, end.location - val.location - 8);
                    return [raw substringWithRange:tid];
                }
            }
        }
    }
    return NSBundle.mainBundle.bundleIdentifier ?: @"unknown";
}

// ─── App binary hash (first 64 KB of main executable) ────────────────────────

static NSString* getAppBinaryHash() {
    NSString* execPath = NSBundle.mainBundle.executablePath;
    if (!execPath) return @"unavailable";
    NSFileHandle* fh = [NSFileHandle fileHandleForReadingAtPath:execPath];
    if (!fh) return @"unavailable";
    NSData* chunk = [fh readDataOfLength:65536];
    [fh closeFile];

    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(chunk.bytes, (CC_LONG)chunk.length, digest);

    NSMutableString* hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

// ─── HMAC-SHA256 via CommonCrypto ─────────────────────────────────────────────

static NSString* hmacSHA256(NSString* message, const uint8_t* key, size_t keyLen) {
    const char* msg = message.UTF8String;
    uint8_t out[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key, keyLen, msg, strlen(msg), out);

    NSMutableString* hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", out[i]];
    return hex;
}

// ─── React Native Module ──────────────────────────────────────────────────────

@interface IntegrityModule : NSObject <RCTBridgeModule>
@end

@implementation IntegrityModule

RCT_EXPORT_MODULE();

/**
 * getAppSum(nonce) — nonce-bound integrity token.
 * Formula: HMAC-SHA256(nonce:teamId:deviceId:binaryHash, NATIVE_SALT)
 */
RCT_EXPORT_METHOD(getAppSum:(NSString*)nonce
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {

    if (isBeingDebugged() || isJailbroken()) {
        reject(@"INTEGRITY_FAIL", @"Compromised environment detected", nil);
        return;
    }

    NSString* teamId     = getSigningTeamId();
    NSString* deviceId   = [UIDevice.currentDevice.identifierForVendor UUIDString] ?: @"unknown";
    NSString* binaryHash = getAppBinaryHash();

    // message: "nonce:teamId:deviceId:binaryHash"
    NSString* message = [NSString stringWithFormat:@"%@:%@:%@:%@",
                         nonce, teamId, deviceId, binaryHash];

    uint8_t salt[SALT_LEN + 1] = {};
    unmaskSalt(salt);
    NSString* appSum = hmacSHA256(message, salt, SALT_LEN);
    memset(salt, 0, sizeof(salt));

    if (appSum.length == 0) {
        reject(@"INTEGRITY_FAIL", @"HMAC computation failed", nil);
        return;
    }
    resolve(appSum);
}

RCT_EXPORT_METHOD(checkEnvironment:(RCTPromiseResolveBlock)resolve
                  rejecter:(__unused RCTPromiseRejectBlock)reject) {
    resolve(@(!isBeingDebugged() && !isJailbroken()));
}

@end
