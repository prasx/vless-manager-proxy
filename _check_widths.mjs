import { createRequire } from 'node:module';
const require = createRequire('C:/Users/Sergey/AppData/Roaming/npm/noop.js');
const puppeteer = require('puppeteer-core');
const browser = await puppeteer.launch({
  executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe',
  headless: true,
  args: ['--no-sandbox', '--disable-gpu', '--hide-scrollbars'],
});
for (const w of [375, 768, 1024, 1100, 1206, 1305, 1440]) {
  const page = await browser.newPage();
  await page.setViewport({ width: w, height: 900 });
  for (const path of ['/', '/sources', '/settings']) {
    await page.goto('http://127.0.0.1:5078' + path, { waitUntil: 'networkidle2' });
    await new Promise(r => setTimeout(r, 900));
    const info = await page.evaluate(() => ({
      sw: document.documentElement.scrollWidth,
      iw: window.innerWidth,
      table: (() => { const t = document.querySelector('.desktop-table'); return t ? getComputedStyle(t).display : null; })(),
      mobile: (() => { const m = document.getElementById('mobileList'); return m ? getComputedStyle(m).display : null; })(),
      srcTable: (() => { const t = document.querySelector('.src-table'); return t ? getComputedStyle(t).display : null; })(),
    }));
    console.log(w, path, JSON.stringify(info));
  }
  await page.close();
}
await browser.close();
