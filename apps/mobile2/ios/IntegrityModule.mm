/**
 * AMoon Eclipse — Runtime Integrity Check (iOS)
 *
 * Computes App-Integrity-Sum using:
 *   - Signing team ID from embedded provisioning profile
 *   - Device identifier (identifierForVendor)
 *   - SECRET_SALT masked in binary (same XOR scheme as Android)
 */

#import <React/RCTBridgeModule.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonHMAC.h>
#import <Security/Security.h>
#include <sys/sysctl.h>
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

    // Suspicious Frida dylibs
    const char* fridaLibs[] = {
        "FridaGadget", "frida", "cynject", "libcycript"
    };
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        if (!name) continue;
        for (auto lib : fridaLibs) {
            if (strstr(name, lib)) return true;
        }
    }

    return false;
}

// ─── Signing info ─────────────────────────────────────────────────────────────

static NSString* getSigningTeamId() {
    // Read embedded provisioning profile (not available in App Store builds
    // without entitlement; use bundle identifier as fallback for distribution).
    NSString* profilePath = [NSBundle.mainBundle pathForResource:@"embedded"
                                                          ofType:@"mobileprovision"];
    if (profilePath) {
        NSData* data = [NSData dataWithContentsOfFile:profilePath];
        if (data) {
            // Extract TeamIdentifier from the plist inside the CMS envelope
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
    // Fallback: use bundle ID (still unique per app, consistent across devices)
    return NSBundle.mainBundle.bundleIdentifier ?: @"unknown";
}

// ─── HMAC-SHA256 via CommonCrypto ─────────────────────────────────────────────

static NSString* hmacSHA256(NSString* message, const uint8_t* key, size_t keyLen) {
    const char* msg = message.UTF8String;
    uint8_t out[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key, keyLen,
           msg, strlen(msg), out);

    NSMutableString* hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", out[i]];
    }
    return hex;
}

// ─── React Native Module ──────────────────────────────────────────────────────

@interface IntegrityModule : NSObject <RCTBridgeModule>
@end

@implementation IntegrityModule

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(getAppSum:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    if (isBeingDebugged()) {
        reject(@"INTEGRITY_FAIL", @"Compromised environment detected", nil);
        return;
    }

    NSString* teamId  = getSigningTeamId();
    NSString* deviceId = [UIDevice.currentDevice.identifierForVendor UUIDString] ?: @"unknown";
    NSString* message  = [NSString stringWithFormat:@"%@:%@", teamId, deviceId];

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
    resolve(@(!isBeingDebugged()));
}

@end
