#!/usr/bin/env python3
"""Drive one Vulhub target end-to-end: docker compose up -> wait for health -> replay a request
corpus through mitmdump's recording proxy -> tear down. Parameterized by target name from
targets.json (see that file for the full 16-target shortlist + per-target notes/license flags).

Usage:
    python3 driver.py --list
    python3 driver.py --target tomcat-cve-2020-1938 --dry-run
    VULHUB_DIR=/path/to/vulhub-checkout python3 driver.py --target tomcat-cve-2020-1938 --out-dir ./out

--dry-run prints the exact plan (compose dir, proxy env, every request the corpus drivers would
fire, teardown) without touching docker, mitmdump, or the network -- use it to sanity-check a
target before actually spinning up a container. This box intentionally has not run a real capture
(no Vulhub checkout, no pulled images) -- --dry-run is how this script's plan gets verified here.

Requires a local `vulhub/vulhub` checkout (MIT, github.com/vulhub/vulhub) at $VULHUB_DIR --
this script does not clone it for you, on the theory that a multi-hundred-directory monorepo
checkout is a deliberate, visible step, not something to trigger as a side effect of a driver run.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST_PATH = os.path.join(HERE, 'targets.json')
ADDON_PATH = os.path.join(HERE, 'record_addon.py')

# Optional external request-corpus drivers. Each is gated on the tool actually being installed
# (shutil.which) -- a target's manifest can list one of these ids in "request_corpus" and the
# driver just skips it with a clear log line if the tool isn't present, rather than failing the
# whole run. See README.md "Request corpus sources" for what to install and where each comes from.
EXTERNAL_DRIVERS = {
    'seclists_raft_medium': {
        'tool': 'feroxbuster',
        'env_var': 'SECLISTS_DIR',
        'source': 'github.com/danielmiessler/SecLists (MIT) -- Discovery/Web-Content/raft-medium-words.txt',
    },
    'nuclei_cve_tag': {
        'tool': 'nuclei',
        'env_var': None,  # nuclei ships its own templates; no extra checkout required
        'source': 'github.com/projectdiscovery/nuclei-templates (MIT), filtered by this target\'s CVE tag',
    },
    'csic_2010_replay': {
        'tool': None,  # handled by replay_line_corpus() below, not an external binary
        'env_var': 'CSIC_2010_PATH',
        'source': 'github.com/msudol/Web-Application-Attack-Datasets (research use) -- raw HTTP request lines',
    },
}


def load_manifest():
    with open(MANIFEST_PATH, encoding='utf-8') as f:
        return json.load(f)


def find_target(manifest, name):
    for t in manifest['targets']:
        if t['name'] == name:
            return t
    return None


def wait_for_health(host, port, timeout=180, interval=3):
    """Poll a plain TCP+HTTP GET / against the container directly (not through the proxy) until it
    answers or timeout elapses. Some targets (GitLab: Rails+Postgres+Redis) take minutes to boot."""
    deadline = time.time() + timeout
    url = f'http://{host}:{port}/'
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                if resp.status:
                    return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def fire(method, path, base_url, proxy_url):
    """One request through the recording proxy via curl -- kept as a subprocess call (not a python
    http client) so the exact bytes on the wire match what a real curl-based PoC in a target's
    README would send, including how curl encodes already-percent-encoded paths."""
    url = base_url.rstrip('/') + path
    cmd = ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '--path-as-is',
           '-x', proxy_url, '-X', method, url]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


def replay_line_corpus(path_file, base_url, proxy_url, method='GET', limit=None):
    """Fire one GET per non-empty, non-comment line of a wordlist/path-list file (SecLists raft
    lists, a funnypot production hit-log dumped as one path per line, or a simplified CSIC replay
    where each line is already just a request path). Generic on purpose: the three corpus sources
    (SecLists, CSIC, funnypot hit logs) all reduce to "a list of paths to GET" once flattened -- a
    full CSIC raw-HTTP-request-line parser is real but not needed for this driver's job of proving
    the plumbing works end to end."""
    count = 0
    with open(path_file, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            fire(method, line if line.startswith('/') else '/' + line, base_url, proxy_url)
            count += 1
            if limit and count >= limit:
                break
    return count


def build_plan(target, out_dir, vulhub_dir, proxy_port, fire_cve_trigger, corpus_limit):
    """Pure planning step (no side effects) -- used by both --dry-run (prints it) and the real run
    (executes it), so the two paths can never silently diverge."""
    compose_dir = os.path.join(vulhub_dir, target['vulhub_dir'])
    proxy_url = f'http://127.0.0.1:{proxy_port}'
    base_url = f'http://127.0.0.1:{target["host_port"]}'

    requests_plan = []
    banner = target['banner_path']
    requests_plan.append(('banner', banner['method'], banner['path']))

    trigger = target.get('cve_trigger') or {}
    if fire_cve_trigger and trigger.get('method') and trigger.get('path'):
        requests_plan.append(('cve_trigger', trigger['method'], trigger['path']))

    external = []
    for driver_id in target.get('request_corpus', []):
        if driver_id in ('banner', 'cve_trigger_optional'):
            continue
        if driver_id in EXTERNAL_DRIVERS:
            external.append(driver_id)

    return {
        'target': target['name'],
        'compose_dir': compose_dir,
        'license_flag': target['license_flag'],
        'server_label': target['server_label'],
        'proxy_url': proxy_url,
        'base_url': base_url,
        'health_check_url': base_url + '/',
        'requests_plan': requests_plan,
        'external_drivers': external,
        'out_dir': out_dir,
        'corpus_limit': corpus_limit,
    }


def print_plan(plan):
    print(f"target:            {plan['target']}")
    print(f"compose dir:       {plan['compose_dir']}")
    print(f"license flag:      {plan['license_flag']}")
    print(f"server label:      {plan['server_label']}")
    print(f"proxy:             {plan['proxy_url']}  (mitmdump -s {ADDON_PATH})")
    print(f"health check:      GET {plan['health_check_url']} (direct, not through proxy)")
    print(f"output dir:        {plan['out_dir']}")
    print('requests fired through the proxy:')
    for kind, method, path in plan['requests_plan']:
        print(f'  [{kind}] {method} {path}')
    if plan['external_drivers']:
        print('external corpus drivers (best-effort, skipped if the tool is not installed):')
        for driver_id in plan['external_drivers']:
            info = EXTERNAL_DRIVERS[driver_id]
            tool_note = f"needs `{info['tool']}`" if info['tool'] else 'built-in line replayer'
            env_note = f", ${info['env_var']}" if info['env_var'] else ''
            print(f"  [{driver_id}] {tool_note}{env_note} -- source: {info['source']}")
    else:
        print('external corpus drivers: none configured for this target')


def run_plan(plan):
    os.makedirs(plan['out_dir'], exist_ok=True)
    env = os.environ.copy()
    env['VULHUB_TARGET'] = plan['target']
    env['VULHUB_SERVER_LABEL'] = plan['server_label']
    env['VULHUB_LICENSE_FLAG'] = plan['license_flag']
    env['VULHUB_OUT_DIR'] = os.path.abspath(plan['out_dir'])

    print(f"[{plan['target']}] docker compose up -d ({plan['compose_dir']})")
    subprocess.run(['docker', 'compose', 'up', '-d'], cwd=plan['compose_dir'], check=True)

    print(f"[{plan['target']}] waiting for {plan['health_check_url']} ...")
    host_port = plan['base_url'].rsplit(':', 1)[1]
    if not wait_for_health('127.0.0.1', host_port):
        print(f"[{plan['target']}] WARNING: health check never returned -- proceeding anyway, "
              f"the recorded corpus may be thin or empty", file=sys.stderr)

    proxy_port = plan['proxy_url'].rsplit(':', 1)[1]
    mitm_cmd = ['mitmdump', '-q', '-s', ADDON_PATH, '-p', proxy_port]
    print(f"[{plan['target']}] starting recording proxy: {' '.join(mitm_cmd)}")
    mitm = subprocess.Popen(mitm_cmd, cwd=HERE, env=env)
    time.sleep(2)  # let mitmdump bind before the first request

    try:
        for kind, method, path in plan['requests_plan']:
            print(f"[{plan['target']}] [{kind}] {method} {path}")
            fire(method, path, plan['base_url'], plan['proxy_url'])

        for driver_id in plan['external_drivers']:
            info = EXTERNAL_DRIVERS[driver_id]
            if info['tool'] and not shutil.which(info['tool']):
                print(f"[{plan['target']}] SKIP [{driver_id}]: `{info['tool']}` not installed")
                continue
            if info['env_var'] and not env.get(info['env_var']):
                print(f"[{plan['target']}] SKIP [{driver_id}]: ${info['env_var']} not set")
                continue
            if driver_id == 'seclists_raft_medium':
                wordlist = os.path.join(env['SECLISTS_DIR'], 'Discovery/Web-Content/raft-medium-words.txt')
                subprocess.run(
                    ['feroxbuster', '--url', plan['base_url'], '--proxy', plan['proxy_url'],
                     '--wordlist', wordlist, '--silent', '--no-state'],
                    timeout=1800, check=False,
                )
            elif driver_id == 'nuclei_cve_tag':
                cve_tag = plan['target'].split('-cve-')[-1] if '-cve-' in plan['target'] else None
                cmd = ['nuclei', '-u', plan['base_url'], '-proxy', plan['proxy_url'], '-silent']
                if cve_tag:
                    cmd += ['-tags', f'cve{cve_tag}']
                subprocess.run(cmd, timeout=1800, check=False)
            elif driver_id == 'csic_2010_replay':
                replay_line_corpus(env['CSIC_2010_PATH'], plan['base_url'], plan['proxy_url'],
                                    limit=plan['corpus_limit'])
    finally:
        print(f"[{plan['target']}] stopping recording proxy")
        mitm.terminate()
        try:
            mitm.wait(timeout=10)
        except subprocess.TimeoutExpired:
            mitm.kill()

        print(f"[{plan['target']}] docker compose down -v")
        subprocess.run(['docker', 'compose', 'down', '-v'], cwd=plan['compose_dir'], check=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--target', help='manifest target name (see --list)')
    ap.add_argument('--list', action='store_true', help='list manifest targets and exit')
    ap.add_argument('--dry-run', action='store_true', help='print the plan, touch nothing')
    ap.add_argument('--out-dir', default='./out', help='where to write ground-truth.jsonl/messages.jsonl')
    ap.add_argument('--vulhub-dir', default=os.environ.get('VULHUB_DIR'),
                     help='path to a local vulhub/vulhub checkout (or $VULHUB_DIR)')
    ap.add_argument('--proxy-port', type=int, default=8080)
    ap.add_argument('--fire-cve-trigger', action='store_true',
                     help='also replay the manifest\'s documented CVE trigger path, not just the safe banner GET')
    ap.add_argument('--corpus-limit', type=int, default=None,
                     help='cap lines fired by line-based external drivers (csic_2010_replay); useful for a smoke test')
    args = ap.parse_args()

    manifest = load_manifest()

    if args.list:
        for t in manifest['targets']:
            flag = '' if t['included'] else ' (extra, not in default 16)'
            print(f"{t['name']:28s} {t['license_flag']:14s} {t['vulhub_dir']}{flag}")
        return 0

    if not args.target:
        ap.error('--target is required (or use --list)')

    target = find_target(manifest, args.target)
    if target is None:
        print(f'unknown target: {args.target} (see --list)', file=sys.stderr)
        return 1

    if not args.dry_run and not args.vulhub_dir:
        ap.error('--vulhub-dir (or $VULHUB_DIR) is required for a real run; use --dry-run to skip it')

    plan = build_plan(
        target, args.out_dir, args.vulhub_dir or '$VULHUB_DIR', args.proxy_port,
        args.fire_cve_trigger, args.corpus_limit,
    )

    if args.dry_run:
        print_plan(plan)
        return 0

    run_plan(plan)
    return 0


if __name__ == '__main__':
    sys.exit(main())
