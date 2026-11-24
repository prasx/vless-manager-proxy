import { createRequire } from 'node:module';
import { mkdirSync } from 'node:fs';
const require = createRequire('C:/Users/Sergey/AppData/Roaming/npm/noop.js');
const puppeteer = require('puppeteer-core');
const OUT = 'D:/git/vless-manager-proxy/.hallmark/after';
mkdirSync(OUT, { recursive: true });
const browser = await puppeteer.launch({
  executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe',
  headless: true,
  args: ['--no-sandbox', '--disable-gpu', '--hide-scrollbars'],
});

for (const [w, h, tag] of [[1206, 800, '1206'], [1305, 900, '1305']]) {
  const page = await browser.newPage();
  await page.setViewport({ width: w, height: h });
  await page.goto('http://127.0.0.1:5083/', { waitUntil: 'networkidle2' });
  await page.waitForSelector('#tbodyDesktop tr', { timeout: 15000 });
  await new Promise(r => setTimeout(r, 1500));
  const geo = await page.evaluate(() => {
    const t = document.querySelector('.desktop-table');
    const tr = t?.querySelector('tbody tr');
    const speed = tr?.querySelector('.speed-cell');
    const act = tr?.querySelector('.actions-cell');
    const r = (el) => { const b = el.getBoundingClientRect(); return { w: Math.round(b.width), r: Math.round(b.right) }; };
    return {
      table: t ? r(t) : null,
      speed: speed ? r(speed) : null,
      actions: act ? r(act) : null,
      speedText: speed?.textContent.replace(/\s+/g, ' ').trim().slice(0, 60),
      scrollW: document.documentElement.scrollWidth,
      innerW: window.innerWidth,
    };
  });
  console.log('dashboard', tag, JSON.stringify(geo));
  await page.screenshot({ path: `${OUT}/tables-dashboard-${tag}.png` });
  await page.close();
}

{
  const page = await browser.newPage();
  await page.setViewport({ width: 1305, height: 900 });
  await page.goto('http://127.0.0.1:5083/sources', { waitUntil: 'networkidle2' });
  await page.waitForSelector('#list .src-table tbody tr', { timeout: 15000 });
  await new Promise(r => setTimeout(r, 1200));
  const geo = await page.evaluate(() => {
    const t = document.querySelector('.src-table');
    const tr = t?.querySelector('tbody tr');
    const act = tr?.querySelector('.src-actions');
    const btns = act ? [...act.querySelectorAll('button')] : [];
    const r = (el) => { const b = el.getBoundingClientRect(); return { l: Math.round(b.left), r: Math.round(b.right), w: Math.round(b.width) }; };
    return {
      table: t ? r(t) : null,
      act: act ? r(act) : null,
      last: btns.length ? r(btns[btns.length - 1]) : null,
      scrollW: document.documentElement.scrollWidth,
      innerW: window.innerWidth,
    };
  });
  console.log('sources', JSON.stringify(geo));
  await page.screenshot({ path: `${OUT}/tables-sources-1305.png` });
  await page.close();
}
await browser.close();
console.log('done');
