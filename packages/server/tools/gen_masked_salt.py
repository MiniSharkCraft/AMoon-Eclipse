#!/usr/bin/env python3
"""
Generate MASKED_SALT bytes for integrity.cpp / IntegrityModule.mm

Usage:
    python3 tools/gen_masked_salt.py "your-secret-salt-here"

Paste the output into the MASKED_SALT[] arrays in both files.
The XOR scheme: masked[i] = plaintext[i] ^ keyAt(i)
where keyAt(i) = MASK_A ^ ((i * MASK_B) & 0xFF)
"""
import sys

MASK_A = 0xA7
MASK_B = 0x3F

def key_at(i: int) -> int:
    return (MASK_A ^ ((i * MASK_B) & 0xFF)) & 0xFF

def mask(salt: str) -> list[int]:
    b = salt.encode()
    return [byte ^ key_at(i) for i, byte in enumerate(b)]

def verify(masked: list[int], salt: str) -> bool:
    recovered = ''.join(chr(b ^ key_at(i)) for i, b in enumerate(masked))
    return recovered == salt

if __name__ == '__main__':
    salt = sys.argv[1] if len(sys.argv) > 1 else 'amoon-eclipse-integrity-salt-v1'
    masked = mask(salt)
    assert verify(masked, salt), "Verification failed!"

    print(f'// Salt: "{salt}" ({len(masked)} bytes)')
    print(f'// Paste into MASKED_SALT[] in integrity.cpp and IntegrityModule.mm')
    print()

    # Format as C array rows of 8 bytes
    rows = [masked[i:i+8] for i in range(0, len(masked), 8)]
    lines = []
    for row in rows:
        lines.append('    ' + ','.join(f'0x{b:02X}' for b in row) + ',')
    print('static const uint8_t MASKED_SALT[] = {')
    print('\n'.join(lines))
    print('};')
    print(f'static constexpr size_t SALT_LEN = {len(masked)};')
