// BlueShift — UI smoke + flow test against the built dist/index.html.
const path = require('path');
const { chromium, firefox, webkit } = require('playwright');
const browserType = { firefox, webkit }[process.env.PLAYWRIGHT_BROWSER] || chromium;
const URL = 'file://' + path.join(__dirname, '..', 'dist', 'index.html');

(async () => {
  const browser = await browserType.launch();
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto(URL, { waitUntil: 'load' });
  await page.waitForSelector('.bs-shell', { timeout: 5000 });

  // Shell + module rail render; SIEM is the active module, future ones are present but disabled.
  if (!(await page.locator('.bs-mod.active').count())) throw new Error('no active module in the rail');
  if ((await page.locator('.bs-mod.soon[disabled]').count()) < 3) throw new Error('future modules should be shown as coming-soon');

  // Alert queue renders.
  const rows = await page.locator('.bs-row').count();
  if (rows < 5) throw new Error('alert queue did not populate (' + rows + ' rows)');

  // KPI tiles and a detail pane for the selected alert.
  if (!(await page.locator('.bs-kpi').count())) throw new Error('no KPI tiles');
  if (!(await page.locator('.bs-detail .bs-log').count())) throw new Error('alert detail did not render raw events');

  // Severity filter narrows the queue; search works.
  await page.selectOption('#bsSev', 'critical'); await page.waitForTimeout(80);
  if (!(await page.locator('.bs-row').evaluateAll(els => els.every(e => e.classList.contains('sev-critical'))))) throw new Error('severity filter did not narrow to critical');
  await page.selectOption('#bsSev', 'all'); await page.waitForTimeout(80);

  // Triage flow: open the first alert, read the model's hidden truth, make the CORRECT call, assert positive feedback.
  await page.locator('.bs-row').first().click(); await page.waitForTimeout(60);
  const truth = await page.evaluate(() => { const id = window.__mods['./ui'].exports.STATE.selected; const env = window.__mods['./ui'].exports.STATE.env; return env.alerts.find(a => a.id === id).truth; });
  if (!truth) throw new Error('could not read selected alert ground truth');
  await page.locator(`.bs-dispo [data-dispo="${truth}"]`).first().click(); await page.waitForTimeout(80);
  if (!(await page.locator('.bs-feedback.good').count())) throw new Error('correct disposition did not show positive feedback');
  // Accuracy score updated to 100% after one correct call.
  const acc = await page.locator('.bs-score strong').textContent();
  if (!/100%/.test(acc)) throw new Error('accuracy should read 100% after one correct triage, got ' + acc);

  // --- SPL search view ---
  await page.click('.bs-subtab[data-view="search"]'); await page.waitForTimeout(80);
  if (!(await page.locator('#bsSpl').count())) throw new Error('SPL search box did not render');

  // Run a stats pipeline and assert a statistics table comes back.
  await page.fill('#bsSpl', 'index=auth action=failure | stats count by user | sort -count');
  await page.click('#bsSplRun'); await page.waitForTimeout(100);
  if (!(await page.locator('.bs-badge.tbl').count())) throw new Error('stats query did not produce a statistics table');
  const headers = await page.$$eval('.bs-table th', ths => ths.map(t => t.textContent));
  if (!(headers.includes('user') && headers.includes('count'))) throw new Error('stats table missing expected columns: ' + headers.join(','));

  // An events query returns raw events.
  await page.fill('#bsSpl', 'index=auth action=failure'); await page.click('#bsSplRun'); await page.waitForTimeout(100);
  if (!(await page.locator('.bs-badge.ev').count())) throw new Error('search did not return events');

  // A bad command surfaces an error, not a crash.
  await page.fill('#bsSpl', '| frobnicate'); await page.click('#bsSplRun'); await page.waitForTimeout(80);
  if (!(await page.locator('.bs-spl-error').count())) throw new Error('unknown command should show an inline error');

  // An example chip loads and runs a query.
  await page.locator('.bs-ex').first().click(); await page.waitForTimeout(100);
  if (!(await page.locator('.bs-table').count())) throw new Error('example query did not run');

  // Back to triage, then new shift resets the score.
  await page.click('.bs-subtab[data-view="triage"]'); await page.waitForTimeout(60);
  await page.click('#bsNewShift'); await page.waitForTimeout(80);
  if ((await page.locator('.bs-score strong').textContent()) !== '—') throw new Error('new shift should reset the accuracy score');

  await browser.close();
  if (errors.length) throw new Error('Browser errors: ' + errors.join(' | '));
  console.log('BlueShift UI test passed (' + browserType.name() + ').');
})().catch(e => { console.error(e); process.exit(1); });
