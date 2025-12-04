#!/usr/bin/env python3
"""
Enumerate Chrome extensions in profiles and write a CSV with basic heuristics for suspicious extensions.
"""
import os, json, csv, datetime, tempfile, shutil
from pathlib import Path
import argparse

# heuristics: suspicious permissions
SUSPICIOUS_PERMISSIONS = set([
    'proxy', 'cookies', 'webRequest', 'webRequestBlocking', 'management', 'nativeMessaging',
    'sockets', 'history', 'downloads', 'tabs', 'browsingData'
])

CHROME_USER_DATA = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data")


def normalize_host(host):
    if not host:
        return ''
    h = host.lower().strip()
    if ':' in h:
        h = h.split(':',1)[0]
    if h.startswith('www.'):
        h = h[4:]
    if h.endswith('.'):
        h = h[:-1]
    return h


def gather_extensions_for_profile(profile_dir):
    """Return list of dicts with extension info"""
    extensions_dir = os.path.join(profile_dir, 'Extensions')
    prefs_file = os.path.join(profile_dir, 'Preferences')
    results = []
    prefs = {}
    if os.path.exists(prefs_file):
        try:
            prefs = json.loads(open(prefs_file, 'r', encoding='utf-8').read())
        except Exception:
            prefs = {}

    settings = {}
    if 'extensions' in prefs:
        settings = prefs.get('extensions', {}).get('settings', {})

    if not os.path.isdir(extensions_dir):
        return results

    for ext_id in os.listdir(extensions_dir):
        ext_path = os.path.join(extensions_dir, ext_id)
        if not os.path.isdir(ext_path):
            continue
        # pick latest version folder
        versions = [d for d in os.listdir(ext_path) if os.path.isdir(os.path.join(ext_path,d))]
        if not versions:
            continue
        versions.sort(key=lambda v: v, reverse=True)
        ver_folder = os.path.join(ext_path, versions[0])
        manifest_path = os.path.join(ver_folder, 'manifest.json')
        manifest = {}
        if os.path.exists(manifest_path):
            try:
                manifest = json.loads(open(manifest_path, 'r', encoding='utf-8').read())
            except Exception:
                manifest = {}
        # gather data
        name = manifest.get('name', manifest.get('short_name', ''))
        version = manifest.get('version', versions[0])
        permissions = manifest.get('permissions', []) or []
        try:
            permissions = [str(p) for p in permissions]
        except Exception:
            permissions = []
        host_permissions = manifest.get('host_permissions', []) or manifest.get('content_scripts', []) or []
        try:
            host_permissions = [str(h) for h in host_permissions]
        except Exception:
            host_permissions = []
        install_type = None
        enabled = None
        settings_entry = settings.get(ext_id)
        if settings_entry:
            enabled = settings_entry.get('state', 0) == 1
            install_type = settings_entry.get('install_type')
        else:
            enabled = True
            install_type = 'unknown'

        # heuristics
        suspicious_reasons = []
        for perm in permissions or []:
            if isinstance(perm, str) and perm in SUSPICIOUS_PERMISSIONS:
                suspicious_reasons.append(f'permission:{perm}')
        # host permissions like <all_urls>
        for hp in host_permissions or []:
            if isinstance(hp, str) and '<all_urls>' in hp:
                suspicious_reasons.append('host:<all_urls>')

        # if name contains ad/miner/crypto
        name_low = (name or '').lower()
        for kw in ('ad', 'miner', 'crypto', 'wallet', 'proxy', 'track'):
            if kw in name_low:
                suspicious_reasons.append(f'name_keyword:{kw}')

        # path mtime (approx last update time)
        update_time = None
        try:
            # Use timezone-aware UTC timestamp instead of deprecated utcfromtimestamp
            update_time = datetime.datetime.fromtimestamp(os.path.getmtime(ver_folder), tz=datetime.timezone.utc)
        except Exception:
            update_time = None

        results.append({
            'profile': os.path.basename(profile_dir),
            'ext_id': ext_id,
            'name': name,
            'version': version,
            'enabled': enabled,
            'install_type': install_type,
            'permissions': ';'.join(permissions) if permissions else '',
            'host_permissions': ';'.join(host_permissions) if isinstance(host_permissions, list) else str(host_permissions),
            'manifest_path': manifest_path,
            'update_time': update_time.isoformat() if update_time else '',
            'suspicious': len(suspicious_reasons) > 0,
            'reasons': ';'.join(suspicious_reasons),
        })
    return results


def scan_profiles(user_data_root, profile_name=None, output_csv='chrome_extensions.csv', debug=False):
    profiles = [profile_name] if profile_name else [p for p in os.listdir(user_data_root) if os.path.isdir(os.path.join(user_data_root,p)) and os.path.isdir(os.path.join(user_data_root,p,'Extensions'))]
    output = []
    for p in profiles:
        profile_dir = os.path.join(user_data_root, p)
        if not os.path.isdir(profile_dir):
            continue
        if debug:
            print(f"Scanning profile: {profile_dir}")
        try:
            exts = gather_extensions_for_profile(profile_dir)
            output.extend(exts)
        except Exception as e:
            if debug:
                print(f"Error scanning {profile_dir}: {e}")
    # write csv
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['profile','ext_id','name','version','enabled','install_type','permissions','host_permissions','manifest_path','update_time','suspicious','reasons'])
        for r in output:
            w.writerow([r['profile'], r['ext_id'], r['name'], r['version'], r['enabled'], r['install_type'], r['permissions'], r['host_permissions'], r['manifest_path'], r['update_time'], r['suspicious'], r['reasons']])
    if debug:
        print(f"Wrote {len(output)} extension records to {output_csv}")
    return output_csv, len(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Export Chrome extensions per profile with heuristics')
    parser.add_argument('--profile', help='Profile folder name (Default, Profile 1, etc.)')
    parser.add_argument('--output', default='chrome_extensions.csv', help='Output CSV file')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()
    root = CHROME_USER_DATA
    scan_profiles(root, profile_name=args.profile, output_csv=args.output, debug=args.debug)
