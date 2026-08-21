#!/usr/bin/env python3
"""Verify app.js against the wasm-bindgen API surface in core/src/wasm.rs.

wasm-bindgen getters become JS properties and everything else becomes a method.
Using the wrong form fails only at runtime ("send.sas is not a function", or a
getter's return value being called), and the app shell has no runtime tests, so
this closes that class of bug at CI time. It exists because a use-after-move on
the same boundary crashed first launch.
"""
import re, sys

RUST = open('core/src/wasm.rs').read()
APP  = open('app/app.js').read()

# type -> {member: 'getter'|'method'}
api = {}
for m in re.finditer(r'#\[wasm_bindgen\]\s*(?:pub struct (\w+)|impl (\w+) \{)', RUST):
    pass
for block in re.finditer(r'#\[wasm_bindgen\]\nimpl (\w+) \{(.*?)\n\}\n', RUST, re.S):
    ty, body = block.group(1), block.group(2)
    api.setdefault(ty, {})
    for fn in re.finditer(r'((?:#\[wasm_bindgen\([^)]*\)\]\s*)*)pub fn (\w+)', body):
        attrs, name = fn.group(1), fn.group(2)
        kind = 'getter' if 'getter' in attrs else \
               'ctor'   if 'constructor' in attrs else 'method'
        api[ty][name] = kind

# JS variable -> wasm type, by naming convention in app.js.
VARS = {
    'session': 'Session', 'recv': 'Receive', 'send': 'Send',
    'r': 'IngestResult', 'f': 'FrameOut', 'qr': 'QrOut',
    'identity': 'Identity', 'id': 'Identity',
}

errors, checked = [], 0
for i, line in enumerate(APP.split('\n'), 1):
    if line.strip().startswith('//'):
        continue
    for m in re.finditer(r'\b(\w+)\.(\w+)(\s*\()?', line):
        var, member, called = m.group(1), m.group(2), bool(m.group(3))
        ty = VARS.get(var)
        if not ty or member not in api.get(ty, {}):
            continue  # a DOM object or an unrelated member; not ours to judge
        kind = api[ty][member]
        checked += 1
        if kind == 'getter' and called:
            errors.append(f'app.js:{i}: {var}.{member}() but {ty}.{member} is a '
                          f'getter; calling it invokes its return value')
        if kind == 'method' and not called:
            errors.append(f'app.js:{i}: {var}.{member} without parens but '
                          f'{ty}.{member} is a method; this reads a function object')

print(f'boundary: {checked} accesses checked against '
      f'{sum(len(v) for v in api.values())} exported members on {len(api)} types')
if errors:
    print('\n'.join(errors)); sys.exit(1)
print('boundary: all access forms match the wasm-bindgen surface')
