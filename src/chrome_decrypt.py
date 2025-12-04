"""Chrome saved-login decryptor (Windows-focused).

Refactored to behave similarly to the Firefox decryptor: can operate over
profiles or a single profile, emits JSON or CSV output, supports non-interactive
mode and continues on non-fatal decryption errors.

IMPORTANT LIMITATION (Chrome v127+, July 2024):
Chrome introduced "App-Bound Encryption" which binds the encryption key to Chrome
itself using the Chrome Elevation Service. Passwords encrypted with v20+ prefix
cannot be decrypted outside of Chrome without access to Chrome's internal services.
This affects passwords saved after Chrome v127 was installed.

Older passwords (v10 prefix) can still be decrypted with this tool.
"""
from __future__ import annotations

import os
import sys
import json
import base64
import sqlite3
import shutil
import tempfile
import argparse
from pathlib import Path
import hashlib
import traceback

try:
    import win32crypt
except ImportError:
    win32crypt = None

try:
    from Cryptodome.Cipher import AES 
except ImportError:
    AES = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
except Exception:
    _AESGCM = None


USERPROFILE = os.environ.get('USERPROFILE', '')
CHROME_USER_DATA = Path(USERPROFILE) / 'AppData' / 'Local' / 'Google' / 'Chrome' / 'User Data'
LOCAL_STATE = CHROME_USER_DATA / 'Local State'

# runtime debug toggle (set from CLI arg)
DEBUG = False


def get_secret_key_from_local_state(local_state_path: Path) -> tuple[bytes | None, bytes | None]:
    """Read Chrome Local State and decrypt the encrypted_key with DPAPI.

    Returns tuple of (regular_key, app_bound_key) - either may be None.
    
    Note: app_bound_key extraction requires Chrome Elevation Service access
    and will typically fail for external tools (Chrome v127+ protection).
    """
    regular_key = None
    app_bound_key = None
    
    try:
        if not local_state_path.exists():
            return None, None
        data = json.loads(local_state_path.read_text(encoding='utf-8'))
        os_crypt = data.get('os_crypt', {})
        
        # Try regular encrypted_key (DPAPI protected)
        enc_key_b64 = os_crypt.get('encrypted_key')
        if enc_key_b64 and win32crypt:
            try:
                enc_key = base64.b64decode(enc_key_b64)
                if enc_key.startswith(b'DPAPI'):
                    enc_key = enc_key[5:]
                regular_key = win32crypt.CryptUnprotectData(enc_key, None, None, None, 0)[1]
            except Exception as e:
                if DEBUG:
                    print(f'[DEBUG] Failed to decrypt regular encrypted_key: {e}', file=sys.stderr)
        
        # Try app_bound_encrypted_key (Chrome v127+ App-Bound Encryption)
        # This typically cannot be decrypted outside of Chrome
        app_bound_b64 = os_crypt.get('app_bound_encrypted_key')
        if app_bound_b64 and win32crypt:
            try:
                app_bound_raw = base64.b64decode(app_bound_b64)
                if app_bound_raw.startswith(b'APPB'):
                    # APPB prefix indicates app-bound encryption
                    # The actual key is DPAPI-encrypted but with Chrome's elevation service
                    # as the required context, so this will fail for external tools
                    enc_part = app_bound_raw[4:]
                    app_bound_key = win32crypt.CryptUnprotectData(enc_part, None, None, None, 0)[1]
            except Exception as e:
                if DEBUG:
                    print(f'[DEBUG] Failed to decrypt app_bound_encrypted_key (expected for v127+): {e}', file=sys.stderr)
                    
    except Exception as e:
        if DEBUG:
            print(f'[DEBUG] Error reading Local State: {e}', file=sys.stderr)
    
    return regular_key, app_bound_key


def generate_derived_keys() -> list[bytes]:
    """Return a list of candidate master keys derived via scrypt/PBKDF2 fallbacks.

    These are tried when Local State DPAPI-unwrap is not available or fails.
    """
    keys = []
    # PBKDF2 'peanuts' legacy fallback (used in some Chromium builds)
    try:
        pb = hashlib.pbkdf2_hmac('sha1', b'peanuts', b'saltysalt', 1, dklen=16)
        keys.append(pb)
    except Exception:
        pass

    # common scrypt parameters seen in some tools
    sparams = [
        (16384, 8, 1, 16),
        (16384, 8, 1, 32),
        (32768, 8, 1, 32),
    ]
    for N, r, p, dklen in sparams:
        try:
            k = hashlib.scrypt(password=b'peanuts', salt=b'saltysalt', n=N, r=r, p=p, dklen=dklen)
            keys.append(k)
        except Exception:
            continue

    # dedupe preserving order
    seen = set()
    out = []
    for k in keys:
        if k in seen:
            continue
        seen.add(k); out.append(k)
    return out


def decrypt_chrome_value(encrypted_value: bytes, secret_key: bytes, app_bound_key: bytes = None) -> tuple[str | None, str]:
    """Decrypt a Chrome encrypted_value (v10/v20...) using AES-GCM and return plaintext.

    Returns tuple of (plaintext, status) where:
    - plaintext is the decrypted string or None on failure
    - status is 'ok', 'v20_app_bound', 'failed', or 'empty'
    
    Chrome AES-GCM format:
    - Prefix: 3 bytes ('v10', 'v20', etc.)
    - Nonce/IV: 12 bytes
    - Ciphertext + Tag: remaining bytes (tag is appended to ciphertext)
    
    Note: v20 prefix typically indicates App-Bound Encryption (Chrome v127+)
    which cannot be decrypted outside of Chrome.
    """
    try:
        if not encrypted_value:
            return None, 'empty'
            
        # Chrome uses a `vXX` prefix (e.g. 'v10', 'v11', 'v20') then a 12-byte nonce
        if isinstance(encrypted_value, (bytes, bytearray, memoryview)) and len(encrypted_value) >= 15 and encrypted_value[0:1] == b'v':
            version_prefix = encrypted_value[:3]
            nonce = encrypted_value[3:15]  # 12-byte nonce
            ciphertext_with_tag = encrypted_value[15:]  # ciphertext + GCM tag (16 bytes)
            
            # Determine which keys to try based on version
            keys_to_try = []
            if version_prefix == b'v20' and app_bound_key:
                # v20 should use app-bound key first
                keys_to_try.append(('app_bound', app_bound_key))
            if secret_key:
                keys_to_try.append(('regular', secret_key))
            if version_prefix == b'v20' and not app_bound_key:
                # v20 without app_bound_key will likely fail
                if DEBUG:
                    print(f'[DEBUG] v20 encrypted value but no app_bound_key available (Chrome v127+ protection)', file=sys.stderr)
            
            for key_name, key in keys_to_try:
                # Try cryptography's AESGCM
                if _AESGCM is not None:
                    try:
                        aesgcm = _AESGCM(key)
                        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
                        if DEBUG:
                            print(f'[DEBUG] AESGCM decrypt success with {key_name} key', file=sys.stderr)
                        return plaintext.decode('utf-8', errors='replace'), 'ok'
                    except Exception as e:
                        if DEBUG:
                            print(f'[DEBUG] AESGCM decrypt failed with {key_name} key: {e}', file=sys.stderr)
                
                # Fallback to PyCryptodome
                if AES is not None and len(ciphertext_with_tag) >= 16:
                    ciphertext = ciphertext_with_tag[:-16]
                    tag = ciphertext_with_tag[-16:]
                    try:
                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                        if DEBUG:
                            print(f'[DEBUG] PyCryptodome AES-GCM success with {key_name} key', file=sys.stderr)
                        return plaintext.decode('utf-8', errors='replace'), 'ok'
                    except Exception as e:
                        if DEBUG:
                            print(f'[DEBUG] PyCryptodome AES-GCM failed with {key_name} key: {e}', file=sys.stderr)
            
            # If v20 and all decryption failed, it's likely app-bound encryption
            if version_prefix == b'v20':
                return None, 'v20_app_bound'
            return None, 'failed'
        else:
            # older Chromium used DPAPI directly on the value
            if win32crypt is None:
                return None, 'failed'
            try:
                plaintext = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode('utf-8', errors='replace')
                return plaintext, 'ok'
            except Exception:
                if DEBUG:
                    print(f'[DEBUG] DPAPI unprotect on entry failed', file=sys.stderr)
                return None, 'failed'
    except Exception:
        if DEBUG:
            traceback.print_exc(file=sys.stderr)
        return None, 'failed'


def extract_logins_from_login_db(login_db_path: Path, secret_key: bytes, app_bound_key: bytes = None) -> tuple[list[dict], dict]:
    """Return list of {url, username, password} from a copied Login Data DB.
    
    Also returns stats dict with counts of successful, failed, and v20_app_bound decryptions.
    """
    results = []
    stats = {'ok': 0, 'failed': 0, 'v20_app_bound': 0, 'empty': 0, 'total': 0}
    if not login_db_path.exists():
        return results, stats
    # copy DB to temp file to safely read while browser may have it locked
    tmpdir = tempfile.mkdtemp(prefix='chrome_login_')
    tmpdb = Path(tmpdir) / 'LoginData.db'
    try:
        shutil.copy2(str(login_db_path), str(tmpdb))
        conn = sqlite3.connect(str(tmpdb))
        cur = conn.cursor()
        cur.execute("SELECT origin_url, username_value, password_value FROM logins")
        
        if DEBUG and secret_key:
            print(f'[DEBUG] Using secret_key len={len(secret_key)} hex={secret_key.hex()}', file=sys.stderr)
        if DEBUG and app_bound_key:
            print(f'[DEBUG] Using app_bound_key len={len(app_bound_key)} hex={app_bound_key.hex()}', file=sys.stderr)

        for origin, username, encpw in cur.fetchall():
            stats['total'] += 1
            pw = None
            status = 'empty'
            
            if encpw:
                if DEBUG:
                    version = encpw[:3].decode('ascii', errors='replace') if len(encpw) >= 3 else '???'
                    print(f'[DEBUG] Entry: url={origin} user={username} version={version} enc_len={len(encpw)}', file=sys.stderr)
                
                pw, status = decrypt_chrome_value(encpw, secret_key, app_bound_key)
                
                if DEBUG:
                    print(f'[DEBUG] Decrypt result: status={status} pw_len={len(pw) if pw else 0}', file=sys.stderr)
            
            stats[status] = stats.get(status, 0) + 1
            results.append({
                'url': origin or '', 
                'user': username or '', 
                'password': pw or '',
                'decrypt_status': status
            })
            
        cur.close()
        conn.close()
    except Exception as e:
        if DEBUG:
            print(f'[DEBUG] Error reading Login Data: {e}', file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
    finally:
        try:
            if tmpdb.exists():
                tmpdb.unlink()
        except Exception:
            pass
        try:
            os.rmdir(tmpdir)
        except Exception:
            pass
    return results, stats


def find_chrome_profile_dirs(root: Path) -> list[Path]:
    """Return list of candidate profile dirs under Chrome User Data.

    Typical names: 'Default', 'Profile 1', 'Profile 2', etc.
    """
    out = []
    if not root.exists():
        return out
    for p in root.iterdir():
        if not p.is_dir():
            continue
        # common profile names
        if p.name == 'Default' or p.name.startswith('Profile') or 'default' in p.name.lower():
            out.append(p)
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description='Chrome saved-login decryptor (Windows).')
    parser.add_argument('profile', nargs='?', help='Path to Chrome profile to decrypt (optional). If omitted, all profiles under User Data are scanned.')
    parser.add_argument('-f', '--format', choices=['json', 'csv'], default='json', help='Output format')
    parser.add_argument('-o', '--output', help='Write output to file (otherwise stdout)')
    parser.add_argument('-n', '--non-interactive', action='store_true', help='Do not prompt; useful for automation')
    parser.add_argument('--debug', action='store_true', help='Print debug information')
    parser.add_argument('--master-key-hex', help='Provide master key (hex) to force decryption (debug)')
    parser.add_argument('--non-fatal-decryption', action='store_true', help='Continue if some profiles fail decryption')
    args = parser.parse_args(argv)

    # enable module-level debug flag for deeper diagnostics
    global DEBUG
    DEBUG = bool(args.debug)

    # load secret keys from Local State once
    secret_key, app_bound_key = get_secret_key_from_local_state(LOCAL_STATE)
    if secret_key is None:
        print('[WARN] Could not obtain Chrome secret key from Local State; DPAPI or Local State missing or unsupported platform', file=sys.stderr)
    if app_bound_key:
        print('[INFO] Successfully extracted app-bound key (rare - usually protected by Chrome Elevation Service)', file=sys.stderr)
    else:
        print('[INFO] App-bound key not available - v20 encrypted passwords (Chrome v127+) cannot be decrypted', file=sys.stderr)
        
    # allow explicit override from CLI for testing
    if args.master_key_hex:
        try:
            mk = bytes.fromhex(args.master_key_hex)
            secret_key = mk
            if DEBUG:
                print(f'[DEBUG] Overriding secret_key from CLI master-key-hex len={len(secret_key)}', file=sys.stderr)
        except Exception as e:
            print(f'[ERROR] invalid --master-key-hex value: {e}', file=sys.stderr)
            return 6

    profiles = []
    if args.profile:
        p = Path(args.profile)
        if p.exists() and p.is_dir():
            profiles = [p]
        else:
            print(f'Profile path not found: {p}', file=sys.stderr)
            return 2
    else:
        profiles = find_chrome_profile_dirs(CHROME_USER_DATA)

    all_results: dict[str, list[dict]] = {}
    total_stats = {'ok': 0, 'failed': 0, 'v20_app_bound': 0, 'empty': 0, 'total': 0}
    
    for p in profiles:
        login_db = p / 'Login Data'
        if not login_db.exists():
            if not args.non_fatal_decryption:
                print(f'[ERROR] Login Data DB not found for profile: {p}', file=sys.stderr)
                return 3
            else:
                if not args.non_interactive:
                    print(f'Skipping profile (no Login Data): {p}', file=sys.stderr)
                continue
        if secret_key is None and win32crypt is None:
            if not args.non_fatal_decryption:
                print('[ERROR] No secret key available and win32crypt not present to DPAPI-decrypt values', file=sys.stderr)
                return 4
        try:
            results, stats = extract_logins_from_login_db(login_db, secret_key, app_bound_key)
            
            # Aggregate stats
            for k in total_stats:
                total_stats[k] += stats.get(k, 0)
            
            if args.debug:
                print(f'[DEBUG] Profile: {p} — entries: {len(results)}, stats: {stats}', file=sys.stderr)

            if results:
                all_results[p.name] = results
        except Exception as e:
            if not args.non_fatal_decryption:
                print(f'[ERROR] Failed to extract logins for {p}: {e}', file=sys.stderr)
                return 5
            else:
                if args.non_interactive:
                    continue
                else:
                    print(f'Warning: failed to extract for {p}: {e}', file=sys.stderr)
                    continue

    # Print summary
    print(f'\n=== Decryption Summary ===', file=sys.stderr)
    print(f'Total entries: {total_stats["total"]}', file=sys.stderr)
    print(f'Successfully decrypted: {total_stats["ok"]}', file=sys.stderr)
    print(f'Empty passwords: {total_stats["empty"]}', file=sys.stderr)
    print(f'v20 App-Bound (Chrome v127+ protected): {total_stats["v20_app_bound"]}', file=sys.stderr)
    print(f'Failed: {total_stats["failed"]}', file=sys.stderr)
    if total_stats["v20_app_bound"] > 0:
        print(f'\n[NOTE] {total_stats["v20_app_bound"]} passwords use Chrome v127+ App-Bound Encryption.', file=sys.stderr)
        print(f'       These cannot be decrypted outside of Chrome due to elevation service protection.', file=sys.stderr)

    # output
    out_data = all_results
    if args.output:
        out_path = Path(args.output)
        if args.format == 'json':
            out_path.write_text(json.dumps(out_data, ensure_ascii=False, indent=2), encoding='utf-8')
        else:
            # CSV: flatten per-profile entries with profile column
            import csv
            with out_path.open('w', newline='', encoding='utf-8') as fh:
                w = csv.writer(fh)
                w.writerow(['profile', 'url', 'user', 'password', 'decrypt_status'])
                for prof, items in out_data.items():
                    for it in items:
                        w.writerow([prof, it.get('url',''), it.get('user',''), it.get('password',''), it.get('decrypt_status','')])
        return 0
    else:
        if args.format == 'json':
            sys.stdout.write(json.dumps(out_data, ensure_ascii=False, indent=2))
        else:
            import csv
            w = csv.writer(sys.stdout)
            w.writerow(['profile', 'url', 'user', 'password', 'decrypt_status'])
            for prof, items in out_data.items():
                for it in items:
                    w.writerow([prof, it.get('url',''), it.get('user',''), it.get('password',''), it.get('decrypt_status','')])
        return 0


if __name__ == '__main__':
    raise SystemExit(main())