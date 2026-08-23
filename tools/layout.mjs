// Phone layout invariants for the built app.
//
//   ./build.sh && python3 tools/serve.py dist 8095 &
//   npm i playwright && node tools/layout.mjs
//
// Exists because the viewfinder shipped twice at the wrong size, the second
// time badly: a `--w` fallback that browsers without `svh` could not use, so
// `width` computed to `auto`, the card took the full column, and the camera's
// intrinsic portrait height burst out of it. Neither showed up in a headless
// Chromium screenshot, because Chromium takes the other branch.
//
// So every viewport is checked on BOTH branches. The no-svh branch is produced
// by intercepting style.css and rewriting every `svh` to a unit no browser
// knows, which is exactly the condition an older Safari is in. That matters:
// the first version of this test forced the fallback by injecting a *valid* vh
// value, and passed cleanly against the very CSS that was broken in the field.
// The bug is not that the fallback computes a different number, it is that the
// declared value is unusable and `width` collapses to `auto`.
//
// Interception rather than an injected <style>: style-src is 'self', so an
// inline stylesheet would be refused, and the point is to test the real file.
import { chromium } from 'playwright';

const PORT = Number(process.env.PORT || 8095);
const CAP_REM = { align: 15, glance: 9.5 };   // must match style.css

const PHONES = [
  ['iPhone SE', 375, 587],
  ['iPhone 13 mini', 375, 715],
  ['iPhone 14', 390, 743],
  ['iPhone 14 Pro Max', 430, 820],
  ['landscape', 844, 320],
];

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM || undefined,
  args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream'],
});

const CSS = await (await fetch(`http://127.0.0.1:${PORT}/style.css`)).text();
if (!CSS.includes('svh')) {
  console.error('style.css has no svh: this test is not exercising what it claims');
  process.exit(1);
}

const failures = [];

for (const [name, w, h] of PHONES) {
  for (const branch of ['svh', 'no-svh']) {
    for (const size of ['align', 'glance']) {
      const ctx = await browser.newContext({ viewport: { width: w, height: h } });
      await ctx.grantPermissions(['camera'], { origin: `http://127.0.0.1:${PORT}` });
      if (branch === 'no-svh') {
        await ctx.route('**/style.css', (route) => route.fulfill({
          contentType: 'text/css',
          body: CSS.replaceAll('svh', 'zqx'), // a unit nothing implements
        }));
      }
      const p = await ctx.newPage();
      await p.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: 'load' });
      await p.waitForTimeout(2500);

      await p.evaluate((s) => { document.getElementById('sight').dataset.size = s; }, size);
      await p.waitForTimeout(500);

      const m = await p.evaluate(() => {
        const de = document.documentElement;
        const sight = document.getElementById('sight').getBoundingClientRect();
        const cam = document.getElementById('camera').getBoundingClientRect();
        return {
          cardW: sight.width, cardH: sight.height,
          camW: cam.width, camH: cam.height,
          camRight: cam.right, camBottom: cam.bottom,
          sightRight: sight.right, sightBottom: sight.bottom,
          scrollW: de.scrollWidth, clientW: de.clientWidth,
          rem: parseFloat(getComputedStyle(de).fontSize),
        };
      });

      const cap = CAP_REM[size] * m.rem;
      const tag = `${name} ${branch}/${size}`;
      const bad = [];
      // The card must never exceed its cap, nor the column.
      if (m.cardW > cap + 1) bad.push(`card ${Math.round(m.cardW)}px > cap ${Math.round(cap)}px`);
      if (m.cardW > m.clientW) bad.push(`card wider than viewport`);
      // The video must stay inside the card it lives in.
      if (m.camRight > m.sightRight + 1 || m.camBottom > m.sightBottom + 1) {
        bad.push(`video ${Math.round(m.camW)}x${Math.round(m.camH)} escapes the card`);
      }
      // And nothing may make the page scroll sideways.
      if (m.scrollW > m.clientW + 1) {
        bad.push(`horizontal overflow: scrollWidth ${m.scrollW} > ${m.clientW}`);
      }

      if (bad.length) {
        failures.push(`${tag}: ${bad.join('; ')}`);
        console.log(`✗ ${tag.padEnd(34)} ${bad.join('; ')}`);
      } else {
        console.log(`✓ ${tag.padEnd(34)} card ${Math.round(m.cardW)}x${Math.round(m.cardH)}, ` +
          `video ${Math.round(m.camW)}x${Math.round(m.camH)}`);
      }
      await ctx.close();
    }
  }
}

await browser.close();
if (failures.length) {
  console.error(`\n=== LAYOUT: ${failures.length} FAILED ===`);
  process.exit(1);
}
console.log('\n=== LAYOUT: PASS ===');
