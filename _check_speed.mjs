import { createRequire } from 'node:module';
const require = createRequire('C:/Users/Sergey/AppData/Roaming/npm/noop.js');
const puppeteer = require('puppeteer-core');
const browser = await puppeteer.launch({
  executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe',
  headless: true,
  args: ['--no-sandbox', '--disable-gpu', '--hide-scrollbars'],
});
const page = await browser.newPage();
await page.setViewport({ width: 1206, height: 800 });
await page.goto('http://127.0.0.1:5083/', { waitUntil: 'networkidle2' });
await page.waitForSelector('#tbodyDesktop tr', { timeout: 15000 });
await page.click('.stat-card[data-filter="working"]');
await new Promise(r => setTimeout(r, 1500));
const data = await page.evaluate(async () => ({
  speed: [...document.querySelectorAll('.speed-cell')].slice(0, 5).map(td => td.textContent.replace(/\s+/g, ' ').trim()),
  max: document.querySelectorAll('.speed-max').length,
  favicon: document.querySelector('link[rel="icon"]')?.getAttribute('href'),
  iconStatus: await fetch(document.querySelector('link[rel="icon"]')?.href || '').then(r => r.status).catch(() => 0),
}));
console.log(JSON.stringify(data));
await page.screenshot({ path: 'D:/git/vless-manager-proxy/.hallmark/after/tables-dashboard-working.png' });
await browser.close();
