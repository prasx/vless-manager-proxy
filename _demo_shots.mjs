import { createRequire } from 'node:module';
const require = createRequire('C:/Users/Sergey/AppData/Roaming/npm/noop.js');
const puppeteer = require('puppeteer-core');
const browser = await puppeteer.launch({
  executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe',
  headless: true,
  args: ['--no-sandbox', '--disable-gpu', '--hide-scrollbars'],
});

{
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1 });
  await page.goto('http://127.0.0.1:5078/', { waitUntil: 'networkidle2' });
  await page.waitForSelector('#tbodyDesktop tr', { timeout: 15000 });
  await new Promise(r => setTimeout(r, 1600));
  await page.click('.stat-card[data-filter="working"]');
  await new Promise(r => setTimeout(r, 1200));
  await page.screenshot({ path: 'D:/git/vless-manager-proxy/docs/dashboard.png' });
  await page.close();
}
{
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1 });
  await page.goto('http://127.0.0.1:5078/sources', { waitUntil: 'networkidle2' });
  await page.waitForSelector('#list .src-table tbody tr', { timeout: 15000 });
  await new Promise(r => setTimeout(r, 1600));
  await page.screenshot({ path: 'D:/git/vless-manager-proxy/docs/sources.png' });
  await page.close();
}
await browser.close();
console.log('screenshots updated');
