"""Fingerprint-safety gate for recorded Vulhub responses.

A real vulnerable app can echo the attacker's own probe back in an error message, log dump, or
reflected-input page -- and that echoed text is often the scanner's own literal signature (a
nuclei `{{BaseURL}}` placeholder, a `matcher_name`, a bare `CVE-xxxx-xxxxx` id, an OOB-callback
domain). Training the honeypot model on that text would teach it to output scanner tells, which
is the opposite of the point. This module is the hard gate: any response body containing one of
these signatures never reaches messages.jsonl.

Mirrors FINGERPRINT_SIGNATURES in funnypot-llm/train/build-galah-corpus.py -- keep the two lists
in sync if either grows; they exist twice because that one gates a different corpus (Galah replay
logs) and importing across train/ and tools/ would couple two independent pipelines together.
"""

FINGERPRINT_SIGNATURES = [
    # Scanner/tool self-identification and matcher artifacts.
    'nuclei', 'cve-', 'matcher', 'interactsh', '{{baseurl}}', 'projectdiscovery',
    'x-nuclei', 'nikto', 'sqlmap', 'acunetix', 'openvas', 'burpcollaborator',
    'oastify', 'w3af', 'qualys', 'nmap', 'feroxbuster', 'ffuf',
    # Out-of-band callback domains the request-corpus drivers may use for blind-RCE templates --
    # if a target's error page reflects the request back, these must not leak into training text.
    'oob.li', 'dnslog', 'ceye.io',
    # Raw JNDI lookup strings (Log4Shell-family payloads) -- if a vulnerable app reflects the
    # attack string in an error page, the literal payload shape is exactly what we don't want the
    # model imitating.
    'jndi:ldap', 'jndi:rmi',
    # Self-revealing honeypot/deception tool names -- a captured page must never look like it came
    # from a *different* honeypot, or training on it teaches the model to unmask itself.
    'honeypot', 'galah', 'decoy', 'canary token', 'cowrie', 'opencanary', 'conpot', 'dionaea',
]


def contains_fingerprint_signature(text: str) -> bool:
    """True if `text` contains any canonical scanner/matcher/self-revealing string. Case-insensitive
    substring match -- deliberately blunt (a false positive just drops one training row; a false
    negative poisons the corpus, so the trade favors over-dropping)."""
    if not text:
        return False
    low = text.lower()
    return any(sig in low for sig in FINGERPRINT_SIGNATURES)
