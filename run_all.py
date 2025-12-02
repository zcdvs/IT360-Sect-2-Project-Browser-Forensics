#!/usr/bin/env python3
"""
Run all Chrome and Firefox analysis scripts and merge CSV outputs into one consolidated CSV.

This script runs the existing exporters as separate processes to avoid import/runtime coupling,
stores outputs in a timestamped `outputs/` directory, and writes a merged CSV containing the
union of all columns from individual CSVs. A `source` column indicates the originating file.
"""
import subprocess
import os
import sys
from pathlib import Path
import datetime
import csv
import argparse
import json

import shutil

# Globals used by run_all() for simple filtering; set by main()
RUN_FILTER_INCLUDE = None
RUN_FILTER_EXCLUDE = None

SCRIPTS = [
    # (label, command args list)
    ("chrome_downloads", [sys.executable, "Browser Data/Chrome/Chrome_Downloads.py", "--output"]),
    ("chrome_history", [sys.executable, "Browser Data/Chrome/Chrome_History.py", "--output"]),
    ("chrome_extensions", [sys.executable, "Browser Data/Chrome/Chrome_Extensions.py", "--output"]),
    ("chrome_sessions", [sys.executable, "Browser Data/Chrome/Chrome_Sessions.py", "--output", "--include-cookie-only", "--full-report"]),
    ("firefox_downloads", [sys.executable, "Browser Data/Firefox/Firefox_Downloads.py", "--output"]),
    ("firefox_history", [sys.executable, "Browser Data/Firefox/Firefox_History.py", "--output", "--full-report"]),
    ("firefox_extensions", [sys.executable, "Browser Data/Firefox/Firefox_Extensions.py", "--output"]),
    ("firefox_sessions", [sys.executable, "Browser Data/Firefox/Firefox_Sessions.py", "--output", "--include-cookie-only", "--full-report"]),
]


def run_all(output_dir: Path, debug=False):
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for label, cmd_base in SCRIPTS:
        # skip scripts that are filtered by global variables (may be adjusted by wrapper)
        if RUN_FILTER_INCLUDE and label not in RUN_FILTER_INCLUDE:
            if debug:
                print(f"Skipping {label} because not in include list")
            continue
        if RUN_FILTER_EXCLUDE and label in RUN_FILTER_EXCLUDE:
            if debug:
                print(f"Skipping {label} because in exclude list")
            continue
        out_path = output_dir / f"{label}.csv"
        # build final command; insert output path after --output position
        cmd = list(cmd_base)
        # find index of '--output' if present, otherwise append
        if '--output' in cmd:
            # replace the next element if placeholder exists, else append
            try:
                idx = cmd.index('--output')
                # ensure there is a following element for path
                if idx == len(cmd) - 1:
                    cmd.append(str(out_path))
                else:
                    cmd[idx+1] = str(out_path)
            except ValueError:
                cmd.extend(['--output', str(out_path)])
        else:
            cmd.extend(['--output', str(out_path)])

        if debug:
            print(f"Running: {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
            results.append((label, out_path, proc.returncode, proc.stdout, proc.stderr))
            if debug:
                print(proc.stdout)
                if proc.stderr:
                    print(proc.stderr)
        except Exception as e:
            results.append((label, out_path, -1, '', str(e)))

    return results


def _derive_record_type(filename: str) -> str:
    fn = filename.lower()
    if 'session' in fn:
        return 'session'
    if 'history' in fn:
        return 'visit'
    if 'download' in fn:
        return 'download'
    if 'extension' in fn or 'extensions' in fn:
        return 'extension'
    return 'other'


def merge_csvs(output_dir: Path, merged_name: str = 'merged_all.csv', filter_token=False, filter_suspicious=False, filter_expr=None):
    csv_files = sorted(list(output_dir.glob('*.csv')))
    if not csv_files:
        return None, 0
    # collect headers union
    headers = set()
    rows = []
    for f in csv_files:
        try:
            with open(f, newline='', encoding='utf-8') as fh:
                rdr = csv.DictReader(fh)
                for r in rdr:
                    r2 = dict(r)
                    r2['_source_file'] = f.name
                    # derive record type from filename
                    r2['record_type'] = _derive_record_type(f.name)

                    # apply simple filters if requested
                    if filter_token:
                        # keep rows where any field contains a token-like marker or token_found column non-empty
                        token_hit = False
                        if r2.get('token_found'):
                            token_hit = True
                        else:
                            for v in r2.values():
                                if isinstance(v, str) and 'token' in v.lower():
                                    token_hit = True
                                    break
                        if not token_hit:
                            continue
                    if filter_suspicious:
                        sus = False
                        # common suspicious columns
                        for col in ('suspicious_flags','suspicious','reasons','cookie_flags'):
                            if r2.get(col):
                                if str(r2.get(col)).strip():
                                    sus = True
                                    break
                        if not sus:
                            continue
                    if filter_expr:
                        # expr in form column:substring or just substring to search any field
                        if ':' in filter_expr:
                            col, substr = filter_expr.split(':',1)
                            if not (col in r2 and substr.lower() in str(r2.get(col,'')).lower()):
                                continue
                        else:
                            found = False
                            for v in r2.values():
                                if isinstance(v, str) and filter_expr.lower() in v.lower():
                                    found = True
                                    break
                            if not found:
                                continue
                    rows.append(r2)
                    headers.update(r2.keys())
        except Exception:
            # skip files that are not CSV or unreadable
            continue

    # ensure deterministic column order: source file last
    headers = list(sorted(h for h in headers if h != '_source_file')) + ['_source_file']
    merged_path = output_dir / merged_name
    with open(merged_path, 'w', newline='', encoding='utf-8') as out_f:
        w = csv.DictWriter(out_f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            # fill missing keys
            row = {k: r.get(k, '') for k in headers}
            w.writerow(row)

    return merged_path, len(rows)


def generate_html_report(output_dir: Path, merged_csv_path: Path, discovered_passwords: dict | None = None, include_passwords: bool = True):
    """Generate a small HTML report summarizing counts per script and suspicious items."""
    per_source = {}
    reason_counts = {}
    total_rows = 0
    total_suspicious = 0
    # collect suspicious extension rows for details
    suspicious_extension_rows = {}

    # helper: map reason code to human-friendly explanation
    REASON_EXPLANATIONS = {
        'permission:proxy': 'Requests proxy permission — can intercept or route network traffic for the browser.',
        'permission:cookies': 'Requests cookie access — can read and modify cookies, potentially hijacking sessions.',
        'permission:webRequest': 'Requests webRequest — can observe/modify network requests (powerful, privacy risk).',
        'permission:webRequestBlocking': 'Requests webRequestBlocking — can synchronously modify or block requests.',
        'permission:management': 'Requests management — can manage other extensions (install/uninstall).',
        'permission:nativeMessaging': 'Requests nativeMessaging — can communicate with native apps on the host.',
        'permission:sockets': 'Requests sockets — can open low-level network sockets.',
        'permission:history': 'Requests history — can read browser history.',
        'permission:downloads': 'Requests downloads permission — can manage or read downloads.',
        'permission:tabs': 'Requests tabs — can read/modify tab URLs and titles.',
        'permission:browsingData': 'Requests browsingData — can remove or examine local browsing data.',
        'host:<all_urls>': 'Has host permission for <all_urls> — extension can access data on any website.',
        'name_keyword:ad': 'Name contains "ad" — may indicate advertising or tracking behavior.',
        'name_keyword:miner': 'Name contains "miner" — may indicate cryptomining functionality.',
        'name_keyword:crypto': 'Name contains "crypto" — may indicate wallet or crypto-related functionality (sensitive).',
        'cookie_insecure': 'Cookie not marked Secure — transmitted over HTTP and may be intercepted.',
        'cookie_http_non_httponly': 'Cookie is accessible to JavaScript (not HttpOnly) — increased XSS risk.',
        'cookie_long_expiry': 'Cookie has a very long expiry — persistent authentication increases exposure risk.',
        'third_party': 'Cookie set for a third-party host — may indicate tracking by third parties.',
        'cookie_wildcard': 'Cookie domain uses a wildcard — cookie sent to multiple subdomains increasing exposure.',
        'token_in_url': 'Token or auth-like value found in URL — may leak via referer, logs, or history.',
        'executable': 'Downloaded file is an executable — potentially dangerous if run.',
        'archive': 'Downloaded archive file — may contain executables or nested payloads.',
        'danger': 'Download marked with danger flag in DB — handled as potentially unsafe by browser.',
    }

    # read merged CSV
    with open(merged_csv_path, newline='', encoding='utf-8') as fh:
        rdr = csv.DictReader(fh)
        for r in rdr:
            total_rows += 1
            src = r.get('_source_file', 'unknown')
            per_source.setdefault(src, {'rows': 0, 'suspicious': 0})
            per_source[src]['rows'] += 1

            # gather reasons from text columns only (avoid boolean 'suspicious' being treated as a reason)
            reasons_found = []
            for col in ('reasons','suspicious_flags','cookie_flags'):
                v = r.get(col)
                if v and isinstance(v, str) and v.strip():
                    # split semicolon-separated lists
                    for part in v.split(';'):
                        p = part.strip()
                        if p:
                            reasons_found.append(p)

            # token_found is a special indicator (may be empty string)
            tf = r.get('token_found')
            if tf and isinstance(tf, str) and tf.strip():
                reasons_found.append('token_in_url')

            # determine boolean suspicious marker without treating as a reason
            sus_bool = False
            s_val = r.get('suspicious')
            if isinstance(s_val, bool):
                sus_bool = s_val
            elif isinstance(s_val, str) and s_val.lower() in ('true','1','yes'):
                sus_bool = True

            # dedupe reasons
            reasons_found = [x for i,x in enumerate(reasons_found) if x and x not in reasons_found[:i]]

            if reasons_found or sus_bool:
                per_source[src]['suspicious'] += 1
                total_suspicious += 1
                # count reasons (prefer explicit reasons; if none but sus_bool, add 'suspicious' marker)
                if reasons_found:
                    for reason in reasons_found:
                        reason_counts[reason] = reason_counts.get(reason, 0) + 1
                else:
                    reason_counts['suspicious'] = reason_counts.get('suspicious', 0) + 1

                # if this source looks like an extensions CSV, record the full row for details
                if 'extension' in src or 'extensions' in src:
                    suspicious_extension_rows.setdefault(src, []).append({'profile': r.get('profile',''), 'id': r.get('ext_id', r.get('id','')), 'name': r.get('name',''), 'reasons': reasons_found or (['suspicious'] if sus_bool else [])})

    # produce HTML
    html_path = output_dir / 'report.html'
    with open(html_path, 'w', encoding='utf-8') as out:
        out.write('<!doctype html>\n<html><head><meta charset="utf-8"><title>Browser Forensics Report</title>')
        out.write('<style>body{font-family:Arial,Helvetica,sans-serif}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px}</style>')
        out.write('</head><body>')
        out.write(f'<h1>Browser Forensics Report</h1>')
        out.write(f'<p>Generated: {datetime.datetime.now().isoformat()}</p>')
        out.write(f'<p>Total rows: {total_rows} — suspicious: {total_suspicious}</p>')
        out.write('<h2>Per-source summary</h2>')
        out.write('<table><tr><th>Source CSV</th><th>Rows</th><th>Suspicious</th></tr>')
        for src, info in sorted(per_source.items(), key=lambda x: -x[1]['rows']):
            out.write(f'<tr><td>{src}</td><td>{info["rows"]}</td><td>{info["suspicious"]}</td></tr>')
        out.write('</table>')

        # Discovered passwords section
        if include_passwords and discovered_passwords:
            out.write('<h2>Discovered Passwords (per profile)</h2>')
            for profile, pwlist in discovered_passwords.items():
                out.write(f'<h3>Profile: {profile} ({len(pwlist)} entries)</h3>')
                out.write('<table><tr><th>Website</th><th>Username</th><th>Password</th></tr>')
                for rec in pwlist:
                    url = rec.get('url','')
                    user = rec.get('user','')
                    pwd = rec.get('password','')
                    out.write(f'<tr><td>{url}</td><td>{user}</td><td>{pwd}</td></tr>')
                out.write('</table>')
        elif discovered_passwords and not include_passwords:
            out.write('<h2>Discovered Passwords</h2>')
            out.write('<p>Passwords were discovered but omitted from this report by request (privacy option).</p>')
        out.write('<h2>All suspicious reasons (with explanations)</h2>')
        out.write('<table><tr><th>Reason</th><th>Count</th><th>Why it matters</th></tr>')
        # show all reasons with a human-friendly explanation when available
        for reason, cnt in sorted(reason_counts.items(), key=lambda x: (-x[1], x[0])):
            # Split reason into base code and optional detail (e.g. "cookie_insecure:ST-abc123")
            if ':' in reason:
                base, detail = reason.split(':', 1)
            else:
                base, detail = reason, ''

            # Prefer an exact mapping first, then fall back to the base code mapping
            expl = REASON_EXPLANATIONS.get(reason) or REASON_EXPLANATIONS.get(base, '')
            # for permission:xxx where we don't have a mapping, provide a generic message
            if not expl and base.startswith('permission:'):
                perm = base.split(':', 1)[1]
                expl = f'Requests permission "{perm}" — may allow elevated access to browser features.'
            if not expl and base.startswith('host:'):
                expl = 'Host-specific permission or suspicious host pattern.'
            if not expl:
                expl = 'Suspicious indicator; review context for details.'

            # If there is a detail (cookie name, host, etc.) include it in the reason column
            reason_display = reason if not detail else f"{base}: {detail}"
            # Also append brief context to the explanation for clarity
            if detail:
                expl = f"{expl} (context: {detail})"

            out.write(f'<tr><td>{reason_display}</td><td>{cnt}</td><td>{expl}</td></tr>')
        out.write('</table>')

        # Detailed suspicious extensions (if any)
        if suspicious_extension_rows:
            out.write('<h2>Suspicious Extensions Details</h2>')
            for src, items in suspicious_extension_rows.items():
                out.write(f'<h3>{src}</h3>')
                out.write('<table><tr><th>Profile</th><th>Extension ID</th><th>Name</th><th>Reasons (with explanation)</th></tr>')
                for it in items:
                    reasons_html = []
                    for rcode in it['reasons']:
                        expl = REASON_EXPLANATIONS.get(rcode, '')
                        if not expl and rcode.startswith('permission:'):
                            perm = rcode.split(':',1)[1]
                            expl = f'Requests permission "{perm}" — may allow elevated access.'
                        if not expl:
                            expl = 'See reason code for context.'
                        reasons_html.append(f"{rcode} — {expl}")
                    out.write(f"<tr><td>{it.get('profile')}</td><td>{it.get('id')}</td><td>{it.get('name')}</td><td>{'<br/>'.join(reasons_html)}</td></tr>")
                out.write('</table>')
        out.write('</body></html>')

    return html_path


def run_firefox_decryptor_for_profiles(debug=False):
    """Run firefox_decryptor.py for each profile directory and return a mapping of profile -> pw list.
    Only include profiles where the decryptor ran successfully and returned JSON output.
    """
    profiles_root = Path(os.environ.get('APPDATA', '')) / 'Mozilla' / 'Firefox' / 'Profiles'
    result = {}
    if not profiles_root.exists():
        return result
    for p in profiles_root.iterdir():
        if not p.is_dir():
            continue
        # Only attempt decryption on profiles that look like real Firefox profiles
        # i.e. they contain `logins.json` and a key DB (`key4.db` or `key3.db`). This
        # avoids trying to run the decryptor against incomplete or non-profile folders
        # which results in NSS initialization errors.
        has_logins = (p / 'logins.json').exists()
        has_key4 = (p / 'key4.db').exists()
        has_key3 = (p / 'key3.db').exists()
        if not has_logins or not (has_key4 or has_key3):
            if debug:
                print(f"Skipping decryptor for {p} — missing logins.json or key4.db/key3.db")
            continue

        profile_path = str(p)
        cmd = [sys.executable, str(Path('Browser Data') / 'Firefox' / 'firefox_decryptor.py'), profile_path, '-f', 'json', '-n', '--non-fatal-decryption']
        if debug:
            print(f"Running decryptor for profile: {profile_path}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except Exception as e:
            if debug:
                print(f"Decryptor failed to start for {profile_path}: {e}")
            continue
        if proc.returncode != 0:
            if debug:
                print(f"Decryptor returned {proc.returncode} for {profile_path}; skipping. Stderr: {proc.stderr}")
            continue
        # parse JSON
        try:
            pwlist = json.loads(proc.stdout)
            # Expect a list of {url,user,password}
            if isinstance(pwlist, list) and pwlist:
                result[p.name] = pwlist
        except Exception as e:
            if debug:
                print(f"Failed to parse decryptor output for {profile_path}: {e}")
            continue
    return result


def main():
    parser = argparse.ArgumentParser(description='Run all browser analysis scripts and merge outputs')
    parser.add_argument('--outdir', default='outputs', help='Directory to store outputs')
    parser.add_argument('--merge-name', default='merged_all.csv', help='Filename for merged CSV')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--include', help='Comma-separated script labels to include (e.g. chrome_sessions,firefox_history)')
    parser.add_argument('--exclude', help='Comma-separated script labels to exclude')
    parser.add_argument('--only', choices=['chrome','firefox','all'], default='all', help='Run only chrome or firefox scripts')
    parser.add_argument('--compress', action='store_true', help='Zip the output folder after run')
    parser.add_argument('--filter-token', action='store_true', help='Keep only rows containing tokens in merged CSV')
    parser.add_argument('--filter-suspicious', action='store_true', help='Keep only rows flagged suspicious in merged CSV')
    parser.add_argument('--filter', help='Generic filter: `column:substring` or `substring` to search any field')
    parser.add_argument('--html-report', action='store_true', help='Produce a small HTML summary report')
    parser.add_argument('--no-passwords', action='store_true', help='Do not include discovered passwords in the HTML report')
    args = parser.parse_args()

    # compute include/exclude lists
    global RUN_FILTER_INCLUDE, RUN_FILTER_EXCLUDE
    RUN_FILTER_INCLUDE = None
    RUN_FILTER_EXCLUDE = None
    if args.include:
        RUN_FILTER_INCLUDE = [s.strip() for s in args.include.split(',') if s.strip()]
    if args.exclude:
        RUN_FILTER_EXCLUDE = [s.strip() for s in args.exclude.split(',') if s.strip()]

    # apply --only filtering
    if args.only != 'all':
        prefix = args.only + '_'
        # if include list present, intersect; else set include list as all matching labels
        matching = [label for label, _ in SCRIPTS if label.startswith(prefix)]
        if RUN_FILTER_INCLUDE is not None:
            RUN_FILTER_INCLUDE = [l for l in RUN_FILTER_INCLUDE if l in matching]
        else:
            RUN_FILTER_INCLUDE = matching

    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    outdir = Path(args.outdir) / ts
    print(f"Outputs will be written to: {outdir}")
    results = run_all(outdir, debug=args.debug)
    for label, path, code, out, err in results:
        print(f"{label}: return={code}, file={path.name}")
        if args.debug and out:
            print(out)
        if args.debug and err:
            print(err)

    merged_path, count = merge_csvs(outdir, merged_name=args.merge_name, filter_token=args.filter_token, filter_suspicious=args.filter_suspicious, filter_expr=args.filter)
    if merged_path:
        print(f"Merged {count} rows into: {merged_path}")
    else:
        print("No CSVs found to merge.")

    discovered_passwords = None
    if args.html_report and not args.no_passwords:
        # attempt to discover passwords per Firefox profile; only include successful profiles
        try:
            discovered_passwords = run_firefox_decryptor_for_profiles(debug=args.debug)
        except Exception as e:
            print(f"Warning: password discovery failed: {e}")

    if args.html_report and merged_path:
        try:
            report_path = generate_html_report(outdir, merged_path, discovered_passwords=discovered_passwords, include_passwords=not args.no_passwords)
            print(f"HTML report: {report_path}")
        except Exception as e:
            print(f"Failed to generate HTML report: {e}")

    if args.compress:
        try:
            # create zip archive of the timestamped folder
            archive_name = str(outdir)
            zip_path = shutil.make_archive(archive_name, 'zip', root_dir=str(outdir))
            print(f"Created archive: {zip_path}")
        except Exception as e:
            print(f"Failed to create archive: {e}")


if __name__ == '__main__':
    main()
