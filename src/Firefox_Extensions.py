#!/usr/bin/env python3
"""
Enumerate Firefox extensions and write CSV with heuristics.
Reads `extensions.json` in each profile and also checks the `extensions` folder for `manifest.json` to gather details.
"""

import os
import json
import csv
from pathlib import Path
import argparse

PROFILES_SUBPATH = Path('Mozilla') / 'Firefox' / 'Profiles'

SUSPICIOUS_PERMISSIONS = set(['nativeMessaging','webRequest','webRequestBlocking','downloads','cookies','geolocation','history','tabs'])


def get_profiles_dir():
    appdata = os.environ.get('APPDATA')
    if not appdata:
        return None
    return Path(appdata) / PROFILES_SUBPATH


def gather_extensions_for_profile(profile_dir: Path, debug=False):
    results = []
    extensions_json = profile_dir / 'extensions.json'
    # Attempt to gather from extensions.json first
    addons = []
    if extensions_json.exists():
        try:
            j = json.loads(open(extensions_json, 'r', encoding='utf-8').read())
            addons = j.get('addons', [])
        except Exception:
            addons = []
    # Parse addon entries
    for a in addons:
        try:
            id_ = a.get('id') or a.get('syncGUID') or ''
            name = a.get('defaultLocale', {}).get('name') if isinstance(a.get('defaultLocale'), dict) else a.get('name')
            version = a.get('version')
            install_type = a.get('type')
            active = a.get('active', False)
            descriptors = a.get('descriptor', '')
            # heuristics — check permissions in the manifest if embedded
            permissions = a.get('permissions', []) or []
            host_permissions = a.get('hostPermissions', []) or []
            suspicious = []
            for perm in permissions:
                if perm in SUSPICIOUS_PERMISSIONS:
                    suspicious.append(f'permission:{perm}')
            for hp in host_permissions:
                if '<all_urls>' in hp or '*' in hp:
                    suspicious.append('host:<all_urls>')
            results.append({'profile': profile_dir.name, 'id': id_, 'name': name, 'version': version, 'active': active, 'install_type': install_type, 'permissions': ';'.join(permissions) if permissions else '', 'host_permissions': ';'.join(host_permissions) if host_permissions else '', 'suspicious': ';'.join(suspicious)})
        except Exception:
            continue

    # Also check the 'extensions' folder for extra manifests
    extensions_dir = profile_dir / 'extensions'
    if extensions_dir.exists():
        for entry in extensions_dir.iterdir():
            try:
                ext_dir = entry
                if not ext_dir.is_dir():
                    # if entry is a .xpi (zip), skip for now
                    continue
                # find manifest.json in nested paths
                for d in ext_dir.iterdir():
                    manifest = d / 'manifest.json'
                    if manifest.exists():
                        m = json.loads(open(manifest, 'r', encoding='utf-8').read())
                        pid = entry.name
                        pname = m.get('name') or m.get('short_name')
                        pver = m.get('version')
                        perms = m.get('permissions', [])
                        host_perms = []
                        if 'host_permissions' in m:
                            host_perms = m.get('host_permissions')
                        if 'content_scripts' in m and isinstance(m.get('content_scripts'), list):
                            # content_scripts may contain matches that behave like host permissions
                            for cs in m.get('content_scripts'):
                                for p in cs.get('matches', []):
                                    host_perms.append(p)
                        suspicious2 = []
                        for perm in perms:
                            if perm in SUSPICIOUS_PERMISSIONS:
                                suspicious2.append(f'permission:{perm}')
                        for hp in host_perms:
                            if '<all_urls>' in hp or '*' in hp:
                                suspicious2.append('host:<all_urls>')
                        results.append({'profile': profile_dir.name, 'id': pid, 'name': pname, 'version': pver, 'active': True, 'install_type': 'folder', 'permissions': ';'.join(perms) if perms else '', 'host_permissions': ';'.join(host_perms) if host_perms else '', 'suspicious': ';'.join(suspicious2)})
            except Exception:
                continue
    return results


def export_extensions(profiles_root, output='firefox_extensions.csv', debug=False):
    profiles_dir = get_profiles_dir()
    if not profiles_dir:
        print('Could not locate Profiles folder')
        return None
    results = []
    for p in profiles_dir.iterdir():
        if not p.is_dir():
            continue
        res = gather_extensions_for_profile(p, debug=debug)
        results.extend(res)
    with open(output, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['profile', 'id', 'name', 'version', 'active', 'install_type', 'permissions', 'host_permissions', 'suspicious'])
        for r in results:
            w.writerow([r['profile'], r['id'], r['name'], r['version'], r['active'], r['install_type'], r['permissions'], r['host_permissions'], r['suspicious']])
    return output, len(results)


def main():
    parser = argparse.ArgumentParser(description='Firefox extensions analysis')
    parser.add_argument('--output', default='firefox_extensions.csv')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()
    out, count = export_extensions(Path(PROFILES_SUBPATH), output=args.output, debug=args.debug)
    print(f'Wrote {count} extensions to {out}')


if __name__ == '__main__':
    main()
