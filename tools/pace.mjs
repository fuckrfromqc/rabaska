// Does the sending screen actually advance at the rate the setting claims?
//
//   ./build.sh && python3 tools/serve.py dist 8141 &
//   node tools/pace.mjs
//
// It did not. The loop slept for a whole period AFTER building and painting a
// frame, so the real interval was the period plus the work — about 45ms of it
// on the machine this was written on, and more on a phone. A nominal 12 frames
// a second came out as 7.5, which made the setting a suggestion and the time
// estimate wrong by the same factor.
//
// That matters more than a wrong label. There is no feedback channel: the
// sender cannot be told the receiver is falling behind, so the only way to fit
// the rate to the two devices and the room is for a person to choose it, and a
// control whose numbers are not real cannot be chosen from.
//
// Paints are counted at CanvasRenderingContext2D.putImageData rather than by
// polling the canvas, because reading a canvas back to compare it costs more
// than the thing being measured and lowers the number it reports.
import { chromium } from 'playwright';

const PORT = Number(process.env.PORT || 8141);
const EXPECT = { steady: 6, fast: 12 };

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM || undefined,
  args: ['--autoplay-policy=no-user-gesture-required'],
});

let failed = false;
try {
  const ctx = await browser.newContext();
  await ctx.addInitScript(() => {
    const c = document.createElement('canvas');
    c.width = c.height = 512;
    const x = c.getContext('2d');
    setInterval(() => { x.fillStyle = '#909090'; x.fillRect(0, 0, 512, 512); }, 60);
    navigator.mediaDevices.getUserMedia = async () => c.captureStream(15);
    window.__paints = 0;
    const put = CanvasRenderingContext2D.prototype.putImageData;
    CanvasRenderingContext2D.prototype.putImageData = function (...a) {
      if (this.canvas.id === 'display') window.__paints++;
      return put.apply(this, a);
    };
  });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => { throw new Error('page error: ' + e.message); });
  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: 'load' });
  await page.waitForTimeout(3000);

  const measure = async (seconds = 4) => {
    const before = await page.evaluate(() => window.__paints);
    await page.waitForTimeout(seconds * 1000);
    const after = await page.evaluate(() => window.__paints);
    return (after - before) / seconds;
  };

  // Big enough that the transfer is still running for both measurements.
  await page.setInputFiles('#file', {
    name: 'k.txt', mimeType: 'text/plain', buffer: Buffer.from('x'.repeat(20000)),
  });
  await page.waitForTimeout(500);
  await page.click('#send-open');   // camera-less, so this needs one device
  await page.waitForTimeout(1500);

  for (const [name, want] of Object.entries(EXPECT)) {
    if (name !== 'steady') {
      // The label, not the input: the radio is visually hidden, which is what
      // a person taps and what a test should therefore tap too.
      await page.click(`.pace label:has(input[value="${name}"])`);
      await page.waitForTimeout(400);
    }
    const got = await measure();
    console.log(`  ${name}: claims ${want}/s, paints ${got.toFixed(1)}/s`);
    // Generous, because setTimeout granularity and a busy machine both cost a
    // little. What this is guarding against is the old behaviour, which was
    // out by 40%, not the last few percent.
    if (Math.abs(got - want) > want * 0.2) {
      throw new Error(`"${name}" claims ${want} frames a second and delivers `
        + `${got.toFixed(1)}. The period has to account for the time spent `
        + 'building and painting the frame, not sit on top of it.');
    }
  }
  console.log('✓ the displayed rate matches the setting');

  const pref = await page.evaluate(() => localStorage.getItem('rabaska:pace'));
  if (pref !== 'fast') throw new Error(`the choice was not remembered: ${pref}`);
  console.log('✓ and the choice is remembered');
  console.log('\n=== PACE: PASS ===');
} catch (e) {
  failed = true;
  console.error('\n=== PACE: FAIL ===\n' + e.message);
} finally {
  await browser.close();
  process.exit(failed ? 1 : 0);
}
