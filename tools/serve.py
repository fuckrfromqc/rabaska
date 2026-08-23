#!/usr/bin/env python3
"""Serve dist/ locally with the real _headers applied.

`python3 -m http.server` is the obvious way to look at dist/, and it is a trap.
It serves none of the headers in `_headers`, so the CSP that governs production
is simply absent locally, and the app you are testing is not the app you deploy.

That gap has already cost something real. The `/*` CSP sets `connect-src 'none'`,
which in production also lands on the service worker script and therefore on the
worker's own scope, where it refuses every `cache.addAll` fetch. Install rejects,
no worker activates, and the offline claim quietly stops being true. Locally,
under `http.server`, the same build installs perfectly and caches all twelve
entries. The bug is invisible in exactly the environment used to look for it.

So: test through this instead.

    ./build.sh && python3 tools/serve.py

localhost is a secure context, so getUserMedia and service workers both work.
"""
import http.server
import os
import re
import socketserver
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else 'dist'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080


def load_rules(root):
    """Parse _headers into [(path pattern, {header: value})], in file order.

    Cloudflare applies every matching rule in order and lets a later one
    overwrite a header an earlier one set, which is what lets `/sw.js` carry a
    different CSP from `/*`. Reproduce that precedence, or this server will not
    reproduce the bug it exists to catch.
    """
    rules, current = [], None
    path = os.path.join(root, '_headers')
    if not os.path.exists(path):
        sys.exit(f'no _headers in {root}: run ./build.sh first')
    for line in open(path):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if not line.startswith((' ', '\t')):
            current = {}
            rules.append((line.strip(), current))
        elif current is not None:
            key, _, value = line.strip().partition(':')
            current[key.strip()] = value.strip()
    return rules


RULES = load_rules(ROOT)


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    def end_headers(self):
        applied = {}
        for pattern, headers in RULES:
            rx = '^' + re.escape(pattern).replace(r'\*', '.*') + '$'
            if re.match(rx, self.path.split('?')[0]):
                applied.update(headers)  # later rule wins, as on Cloudflare
        for key, value in applied.items():
            self.send_header(key, value)
        super().end_headers()


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(('127.0.0.1', PORT), Handler) as httpd:
        print(f'serving {ROOT} with production headers on http://127.0.0.1:{PORT}')
        print('the CSP is enforced here, which is the whole point')
        httpd.serve_forever()
