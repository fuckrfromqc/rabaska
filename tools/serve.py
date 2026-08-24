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
    """Parse _headers into [(path pattern, [(header, value), ...])], in file order.

    Cloudflare applies every matching rule and APPENDS repeated headers rather
    than replacing them. This server merged them into a dict instead, so a
    response that production sends with two Content-Security-Policy headers
    came back with one here. That is not a cosmetic difference: two policies
    are both enforced and a request must satisfy both, so the merged version
    was strictly more permissive than production and reported a precache
    working that had never worked in the field. A list, not a dict, because
    the duplication is the behaviour being reproduced.
    """
    rules, current = [], None
    path = os.path.join(root, '_headers')
    if not os.path.exists(path):
        sys.exit(f'no _headers in {root}: run ./build.sh first')
    for line in open(path):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if not line.startswith((' ', '\t')):
            current = []
            rules.append((line.strip(), current))
        elif current is not None:
            key, _, value = line.strip().partition(':')
            current.append((key.strip(), value.strip()))
    return rules


RULES = load_rules(ROOT)


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    def end_headers(self):
        path = self.path.split('?')[0]
        for pattern, headers in RULES:
            rx = '^' + re.escape(pattern).replace(r'\*', '.*') + '$'
            if re.match(rx, path):
                for key, value in headers:
                    self.send_header(key, value)  # appended, as on Cloudflare
        super().end_headers()


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(('127.0.0.1', PORT), Handler) as httpd:
        print(f'serving {ROOT} with production headers on http://127.0.0.1:{PORT}')
        print('the CSP is enforced here, which is the whole point')
        httpd.serve_forever()
