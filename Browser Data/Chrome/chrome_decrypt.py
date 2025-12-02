"""Chrome saved-login decryptor (Windows-focused).

Refactored to behave similarly to the Firefox decryptor: can operate over
profiles or a single profile, emits JSON or CSV output, supports non-interactive
mode and continues on non-fatal decryption errors.
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
except Exception:
    win32crypt = None

try:
    from Cryptodome.Cipher import AES
except Exception:
    try:
        from Crypto.Cipher import AES
    except Exception:
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


def get_secret_key_from_local_state(local_state_path: Path) -> bytes | None:
    """Read Chrome Local State and decrypt the encrypted_key with DPAPI.

    Returns raw AES key bytes or None on failure.
    """
    try:
        if not local_state_path.exists():
            return None
        data = json.loads(local_state_path.read_text(encoding='utf-8'))
        enc_key_b64 = data.get('os_crypt', {}).get('encrypted_key')
        if not enc_key_b64:
            return None
        enc_key = base64.b64decode(enc_key_b64)
        # strip DPAPI prefix
        if enc_key.startswith(b'DPAPI'):
            enc_key = enc_key[5:]
        if win32crypt is None:
            return None
        # DPAPI decrypt
        return win32crypt.CryptUnprotectData(enc_key, None, None, None, 0)[1]
    except Exception:
        return None


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


def decrypt_chrome_value(encrypted_value: bytes, secret_key: bytes) -> str | None:
    """Decrypt a Chrome encrypted_value (v10...) using AES-GCM and return plaintext.

    Returns None on failure.
    """
    try:
        if not encrypted_value:
            return None
        # Chrome uses a `vXX` prefix (e.g. 'v10', 'v11', 'v20') then a 12-byte IV,
        # ciphertext, and 16-byte tag. Accept any version that starts with 'v'.
        if isinstance(encrypted_value, (bytes, bytearray, memoryview)) and len(encrypted_value) >= 31 and encrypted_value[0:1] == b'v':
            iv = encrypted_value[3:15]
            tag = encrypted_value[-16:]
            ciphertext = encrypted_value[15:-16]
            # Try decrypt with no AAD first, then try some common AAD variants (version prefix)
            aad_candidates = [None, encrypted_value[:3]]
            for aad in aad_candidates:
                try:
                    cipher = AES.new(secret_key, AES.MODE_GCM, iv)
                    if aad is not None:
                        cipher.update(aad)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    if DEBUG:
                        print(f'[DEBUG] AES-GCM success with aad={aad}', file=sys.stderr)
                    return plaintext.decode('utf-8', errors='replace')
                except Exception as e:
                    if DEBUG:
                        try:
                            key_sample = secret_key.hex()[:32]
                        except Exception:
                            key_sample = '<unk>'
                        try:
                            ct_sample = ciphertext[:32].hex()
                        except Exception:
                            ct_sample = '<unk>'
                        aad_desc = '<none>' if aad is None else (aad.hex() if isinstance(aad, (bytes,bytearray)) else str(aad))
                        print(f'[DEBUG] AES-GCM failed (aad={aad_desc}): key={key_sample} iv={iv.hex()} ct_sample={ct_sample} tag={tag.hex()} err={e}', file=sys.stderr)
                        traceback.print_exc(file=sys.stderr)
            # Try cryptography AESGCM decrypt on combined ciphertext+tag (some implementations expect combined input)
            if _AESGCM is not None:
                try:
                    combined = encrypted_value[15:]
                    aesgcm = _AESGCM(secret_key)
                    aad = encrypted_value[:3]
                    try:
                        pt = aesgcm.decrypt(iv, combined, None)
                        if DEBUG:
                            print(f'[DEBUG] AESGCM.decrypt success (no AAD) key={secret_key.hex()[:32]} iv={iv.hex()}', file=sys.stderr)
                        return pt.decode('utf-8', errors='replace')
                    except Exception:
                        # try with version prefix as AAD
                        pt = aesgcm.decrypt(iv, combined, aad)
                        if DEBUG:
                            print(f'[DEBUG] AESGCM.decrypt success (with AAD) key={secret_key.hex()[:32]} iv={iv.hex()}', file=sys.stderr)
                        return pt.decode('utf-8', errors='replace')
                except Exception as e:
                    if DEBUG:
                        print(f'[DEBUG] AESGCM.decrypt fallback failed: {e}', file=sys.stderr)
                        traceback.print_exc(file=sys.stderr)
            return None
        else:
            # older Chromium used DPAPI directly on the value
            if win32crypt is None:
                return None
            try:
                return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode('utf-8', errors='replace')
            except Exception:
                if DEBUG:
                    print(f'[DEBUG] DPAPI unprotect on entry failed', file=sys.stderr)
                return None
    except Exception:
        if DEBUG:
            traceback.print_exc(file=sys.stderr)
        return None


def extract_logins_from_login_db(login_db_path: Path, secret_key: bytes) -> list[dict]:
    """Return list of {url, username, password} from a copied Login Data DB."""
    results = []
    if not login_db_path.exists():
        return results
    # copy DB to temp file to safely read while browser may have it locked
    tmpdir = tempfile.mkdtemp(prefix='chrome_login_')
    tmpdb = Path(tmpdir) / 'LoginData.db'
    try:
        shutil.copy2(str(login_db_path), str(tmpdb))
        conn = sqlite3.connect(str(tmpdb))
        cur = conn.cursor()
        cur.execute("SELECT origin_url, username_value, password_value FROM logins")
        # prepare candidate keys: prefer provided secret_key, but include derived fallbacks
        candidate_keys = []
        if secret_key:
            candidate_keys.append(secret_key)
        candidate_keys.extend(generate_derived_keys())
        if DEBUG:
            try:
                print(f'[DEBUG] Local State secret_key len={len(secret_key)} hex={secret_key.hex()}', file=sys.stderr)
            except Exception:
                print('[DEBUG] Local State secret_key present (unable to hex-print)', file=sys.stderr)
        if DEBUG:
            for idx, k in enumerate(candidate_keys):
                try:
                    print(f'[DEBUG] candidate key[{idx}] len={len(k)} hex={k.hex()}', file=sys.stderr)
                except Exception:
                    print(f'[DEBUG] candidate key[{idx}] present (unable to hex-print)', file=sys.stderr)
        # additional derived candidates from the Local State key (common heuristics)
        try:
            if secret_key:
                extra = []
                # first/second halves
                if len(secret_key) >= 16:
                    extra.append(secret_key[:16])
                if len(secret_key) >= 32:
                    extra.append(secret_key[16:32])
                # SHA256 of secret_key
                try:
                    extra.append(hashlib.sha256(secret_key).digest())
                except Exception:
                    pass
                # add uniques
                for ek in extra:
                    if ek not in candidate_keys:
                        candidate_keys.append(ek)
                if DEBUG:
                    for idx, k in enumerate(candidate_keys):
                        try:
                            print(f'[DEBUG] post-extra candidate key[{idx}] len={len(k)} hex={k.hex()}', file=sys.stderr)
                        except Exception:
                            print(f'[DEBUG] post-extra candidate key[{idx}] present', file=sys.stderr)
        except Exception:
            pass

        for origin, username, encpw in cur.fetchall():
            pw = None
            if encpw is not None:
                if DEBUG:
                    try:
                        sample_hex = (encpw[:64].hex() if isinstance(encpw, (bytes, bytearray, memoryview)) else str(encpw))
                    except Exception:
                        sample_hex = '<unprintable>'
                    print(f'[DEBUG] trying entry url={origin} user={username} enc_len={len(encpw) if encpw is not None else 0} sample={sample_hex}', file=sys.stderr)

                # try each candidate key until one yields a non-empty result
                for idx, k in enumerate(candidate_keys):
                    try:
                        dec = decrypt_chrome_value(encpw, k)
                    except Exception as e:
                        dec = None
                        if DEBUG:
                            print(f'[DEBUG] key[{idx}] raised exception: {e}', file=sys.stderr)
                            traceback.print_exc(file=sys.stderr)
                    if dec is not None:
                        if DEBUG:
                            print(f'[DEBUG] key[{idx}] produced plaintext len={len(dec)}', file=sys.stderr)
                        # accept even empty-string result (explicit decryption)
                        pw = dec
                        break

                # as last resort, if DPAPI is available and not already tried, try it
                if pw is None and win32crypt is not None:
                    try:
                        dp = win32crypt.CryptUnprotectData(encpw, None, None, None, 0)[1].decode('utf-8', errors='replace')
                        if dp is not None:
                            pw = dp
                            if DEBUG:
                                print(f'[DEBUG] DPAPI fallback produced plaintext len={len(dp)}', file=sys.stderr)
                    except Exception as e:
                        if DEBUG:
                            print(f'[DEBUG] DPAPI fallback failed: {e}', file=sys.stderr)
                            traceback.print_exc(file=sys.stderr)

            results.append({'url': origin or '', 'user': username or '', 'password': pw or ''})
        cur.close()
        conn.close()
    except Exception:
        # return what we have so far
        pass
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
    return results


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

    # load secret key from Local State once
    secret_key = get_secret_key_from_local_state(LOCAL_STATE)
    if secret_key is None:
        print('[WARN] Could not obtain Chrome secret key from Local State; DPAPI or Local State missing or unsupported platform', file=sys.stderr)
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
            results = extract_logins_from_login_db(login_db, secret_key)
            if args.debug:
                print(f'[DEBUG] Profile: {p} — entries: {len(results)}', file=sys.stderr)
                # print a sample of the first entry internals by reading DB directly
                try:
                    import sqlite3
                    tmp = tempfile.mkdtemp(prefix='chrome_dbg_')
                    tmpdb = Path(tmp) / 'db.db'
                    shutil.copy2(str(login_db), str(tmpdb))
                    conn = sqlite3.connect(str(tmpdb))
                    cur = conn.cursor()
                    cur.execute("SELECT origin_url, username_value, password_value FROM logins LIMIT 3")
                    for origin, username, encpw in cur.fetchall():
                        t = type(encpw)
                        l = len(encpw) if encpw is not None else 0
                        sample = (encpw[:16].hex() if isinstance(encpw, (bytes,bytearray,memoryview)) and l>0 else str(encpw)[:64])
                        dec = None
                        try:
                            dec = decrypt_chrome_value(encpw, secret_key)
                        except Exception as _:
                            dec = None
                        print(f'[DEBUG ROW] url={origin} user={username} enc_type={t} enc_len={l} enc_sample={sample} decrypted={dec}', file=sys.stderr)
                    cur.close()
                    conn.close()
                except Exception as _:
                    pass

            if results:
                all_results[p.name] = results
        except Exception as e:
            if not args.non_fatal_decryption:
                print(f'[ERROR] Failed to extract logins for {p}: {e}', file=sys.stderr)
                return 5
            else:
                if args.non_interactive:
                    # silently continue
                    continue
                else:
                    print(f'Warning: failed to extract for {p}: {e}', file=sys.stderr)
                    continue

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
                w.writerow(['profile', 'url', 'user', 'password'])
                for prof, items in out_data.items():
                    for it in items:
                        w.writerow([prof, it.get('url',''), it.get('user',''), it.get('password','')])
        return 0
    else:
        if args.format == 'json':
            sys.stdout.write(json.dumps(out_data, ensure_ascii=False, indent=2))
        else:
            import csv
            w = csv.writer(sys.stdout)
            w.writerow(['profile', 'url', 'user', 'password'])
            for prof, items in out_data.items():
                for it in items:
                    w.writerow([prof, it.get('url',''), it.get('user',''), it.get('password','')])
        return 0


if __name__ == '__main__':
    raise SystemExit(main())