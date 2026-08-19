"""mitmdump addon: run as `mitmdump -s record_addon.py -p 8080`.

Every completed flow gets appended as one line to ground-truth.jsonl and, if it survives the
fingerprint-safety gate in recorder_core.build_messages_record, one line to messages.jsonl.

Deliberately does not `import mitmproxy` at module level -- mitmproxy passes its Flow object into
`response(flow)` at call time, and every field this file reads (`.request.method`, `.headers`,
`.content`, ...) is accessed by attribute, not by type. That means this file's own logic can be
exercised by selftest.py with a bare python3 and a small fake Flow object -- no mitmproxy install,
no proxy, no docker needed to validate the JSONL shaping.

Env vars (set per docker-compose run by driver.py, see targets.json for the values per target):
  VULHUB_TARGET        manifest target name -- tags every record as source_container
  VULHUB_SERVER_LABEL  stack label used when the response carries no Server header
  VULHUB_LICENSE_FLAG  "oss" | "internal_only" -- copied onto every ground-truth row so a later
                        step can never accidentally fold an internal-only capture into a
                        redistributable corpus
  VULHUB_OUT_DIR        directory to write ground-truth.jsonl / messages.jsonl into (default: cwd)
"""
import json
import os

from recorder_core import build_ground_truth_record, build_messages_record

OUT_DIR = os.environ.get('VULHUB_OUT_DIR', '.')
GROUND_TRUTH_PATH = os.path.join(OUT_DIR, 'ground-truth.jsonl')
MESSAGES_PATH = os.path.join(OUT_DIR, 'messages.jsonl')


def _headers_as_list(headers):
    """Accepts mitmproxy's Headers (has .items(multi=True), preserves repeated header names), a
    plain dict, or an already-flat list of (name, value) pairs -- the last two let selftest.py
    hand this function plain data without building a fake mitmproxy Headers object."""
    if not headers:
        return []
    if hasattr(headers, 'items'):
        try:
            return list(headers.items(multi=True))
        except TypeError:
            return list(headers.items())
    return list(headers)


def _decode(content):
    if content is None:
        return ''
    if isinstance(content, bytes):
        return content.decode('utf-8', errors='replace')
    return str(content)


def _split_path_query(full_path):
    if '?' in full_path:
        path, query = full_path.split('?', 1)
        return path, query
    return full_path, ''


def _append_jsonl(path, record):
    with open(path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(record, ensure_ascii=False) + '\n')


def extract_and_build(flow):
    """The addon's actual work, split out from response() so selftest.py can call it directly on a
    fake flow and get back (ground_truth_record, messages_record_or_None) without touching disk."""
    req = flow.request
    resp = flow.response

    path, query = _split_path_query(req.path)
    gt = build_ground_truth_record(
        method=req.method,
        path=path,
        query=query,
        req_headers=_headers_as_list(req.headers),
        req_body=_decode(req.content),
        status=resp.status_code,
        resp_headers=_headers_as_list(resp.headers),
        resp_body=_decode(resp.content),
        source_container=os.environ.get('VULHUB_TARGET', 'unknown'),
        license_flag=os.environ.get('VULHUB_LICENSE_FLAG', 'oss'),
    )
    msg = build_messages_record(
        method=gt['method'],
        path=gt['path'],
        resp_body=gt['resp_body'],
        resp_headers=gt['resp_headers'],
        server_label=os.environ.get('VULHUB_SERVER_LABEL'),
    )
    return gt, msg


def response(flow):
    """mitmdump's per-flow hook -- called once the response side of a flow is complete."""
    if flow.response is None:
        return
    gt, msg = extract_and_build(flow)
    _append_jsonl(GROUND_TRUTH_PATH, gt)
    if msg is not None:
        _append_jsonl(MESSAGES_PATH, msg)
