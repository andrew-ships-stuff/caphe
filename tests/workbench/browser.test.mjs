import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFile} from 'node:fs/promises';
const url=process.env.CAPHE_UI_TEST_URL;
test('workbench browser workflow, accessibility, and responsive layout',{skip:!url,timeout:120000},async()=>{
 const require=createRequire(new URL('../../website/package.json',import.meta.url));
 const {chromium,expect}=require('@playwright/test');
 const {default:AxeBuilder}=await import(require.resolve('@axe-core/playwright'));
 const browser=await chromium.launch({headless:true});
 try {
  const context=await browser.newContext({viewport:{width:1440,height:1000}});const page=await context.newPage();
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.goto(url);await page.evaluate(()=>document.fonts.ready);
  await expect(page.getByRole('heading',{name:'The attention queue.'})).toBeVisible();
  await expect(page.locator('.brand img')).toHaveAttribute('src','/caphe-mark.png');
  await page.getByLabel('Search findings',{exact:true}).fill('24790');
  await expect(page.locator('tr.finding')).toHaveCount(1);
  await page.getByLabel('Filter by severity').selectOption('low');
  await expect(page.getByRole('heading',{name:'No findings match this view'})).toBeVisible();
  await page.getByRole('button',{name:'Clear filters'}).click();
  await page.getByRole('tab',{name:'New 3',exact:true}).click();
  await expect(page.locator('tr.finding')).toHaveCount(3);
  await page.locator('tr[data-value="CP-0142"]').click();
  await page.getByRole('tab',{name:'Fix',exact:true}).click();
  await expect(page.locator('.code-line.add')).toContainText('go 1.22.4');
  await page.getByRole('tab',{name:'History',exact:true}).click();
  await expect(page.locator('.timeline')).toContainText('First observed');
  await page.locator('.case-footer [data-action="triage"]').click();
  await page.getByLabel('Remediation state').selectOption('In review');
  await page.getByLabel('Investigation note').fill('Review ownership and verify the patch.');
  await page.getByRole('button',{name:'Save local triage'}).click();
  await expect(page.locator('tr[data-value="CP-0142"] .state')).toContainText('In review');
  await page.locator('.case-footer [data-action="triage"]').click();
  await page.getByLabel('Remediation state').selectOption('Accepted');
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await expect(page.locator('tr[data-value="CP-0142"] .state')).toContainText('In review');
  await page.getByRole('separator').focus();await page.keyboard.press('ArrowLeft');
  await expect(page.getByRole('separator')).toHaveAttribute('aria-valuenow','458');
  await page.getByRole('button',{name:'Save current view'}).click();
  await page.getByLabel('View name').fill('New findings');await page.getByRole('button',{name:'Save view',exact:true}).click();
  await page.getByLabel('Sort findings').selectOption('recent');
  await page.getByLabel('Group findings').selectOption('repo');
  await expect(page.locator('.group-row')).toHaveCount(2);
  await page.getByLabel('Select all visible findings').check();
  await page.getByRole('button',{name:'Mark in review'}).click();
  await expect(page.locator('tr.finding .state').filter({hasText:'In review'})).toHaveCount(3);
  const download=page.waitForEvent('download');await page.getByRole('button',{name:'Export visible findings',exact:true}).click();
  assert.equal((await download).suggestedFilename(),'caphe-findings.csv');
  await page.keyboard.press('Control+k');await page.getByLabel('Search commands and findings').fill('Assets');
  await page.keyboard.press('ArrowDown');await page.keyboard.press('Enter');
  await expect(page.getByRole('heading',{name:'Asset inventory.'})).toBeVisible();
  await page.getByRole('button',{name:'Overview',exact:true}).click();
  await page.getByRole('tab',{name:/All attention/}).click();
  await page.getByLabel('Group findings').selectOption('none');
  await page.getByRole('button',{name:'Toggle color theme'}).click();
  const dark=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa']).analyze();
  assert.deepEqual(dark.violations.map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[]);
  await page.getByRole('button',{name:'Toggle color theme'}).click();
  const light=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa']).analyze();
  assert.deepEqual(light.violations.map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[]);
  await page.screenshot({path:'/tmp/caphe-workbench-desktop.png'});
  await page.reload();await expect(page.locator('tr[data-value="CP-0142"] .state')).toContainText('In review');
  for(const width of [1920,1024,390]) {
   await page.setViewportSize({width,height:900});await page.goto(url);
   await expect(page.locator('.surface')).toBeVisible();
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
   if(width===390){if(await page.getByRole('button',{name:'Close investigation'}).isVisible())await page.getByRole('button',{name:'Close investigation'}).click();await page.getByRole('button',{name:'Toggle navigation'}).click();await page.getByRole('button',{name:'Settings',exact:true}).click();await expect(page.getByRole('heading',{name:'Workbench settings.'})).toBeVisible();await page.screenshot({path:'/tmp/caphe-workbench-mobile.png'});const mobile=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa']).analyze();assert.deepEqual(mobile.violations.map(v=>v.id),[])}
  }
  assert.deepEqual(errors,[]);
 } finally {await browser.close()}
});

test('live cluster connection through deployed workbench',{skip:!url||!process.env.CAPHE_TEST_AUTH_FILE,timeout:60000},async()=>{
 const require=createRequire(new URL('../../website/package.json',import.meta.url));
 const {chromium,expect}=require('@playwright/test');
 const auth=JSON.parse(await readFile(process.env.CAPHE_TEST_AUTH_FILE,'utf8'));
 const browser=await chromium.launch({headless:true});
 try{const context=await browser.newContext({viewport:{width:1440,height:1000}});const page=await context.newPage();await page.goto(url);
 await page.getByRole('button',{name:'Connect API',exact:true}).click();await page.getByLabel('Tenant bearer token').fill('invalid-token-for-browser-test-000000000000');await page.getByRole('button',{name:'Connect cluster',exact:true}).click();await expect(page.locator('#form-error')).toContainText('Invalid tenant token');await page.getByLabel('Tenant bearer token').fill(auth.tokens[0].token);
 await page.getByRole('button',{name:'Connect cluster',exact:true}).click();
 await expect(page.getByText('LIVE CLUSTER',{exact:true})).toBeVisible();await expect(page.locator('.loading-line')).toHaveCount(0,{timeout:30000});
 await expect(page.locator('.error-banner')).toHaveCount(0);
 await page.getByRole('button',{name:'Runs',exact:true}).click();await expect(page.getByRole('heading',{name:'Analysis runs.'})).toBeVisible();
 await expect(page.locator('.data-list tbody tr').first()).toBeVisible();
 await page.getByLabel('Comparison baseline').selectOption({index:1});await expect(page.locator('.loading-line')).toHaveCount(0,{timeout:30000});await expect(page.locator('.error-banner')).toHaveCount(0);await expect(page.locator('#toast')).toContainText('Comparison loaded');
 await page.getByRole('button',{name:'Settings',exact:true}).click();await page.getByRole('button',{name:'Disconnect',exact:true}).click();
 await expect(page.getByText('SAMPLE DATA',{exact:true})).toBeVisible();
 }finally{await browser.close()}
});

test('disconnect discards an in-flight live dossier',{skip:!url||!process.env.CAPHE_TEST_AUTH_FILE,timeout:60000},async()=>{
 const require=createRequire(new URL('../../website/package.json',import.meta.url));
 const {chromium,expect}=require('@playwright/test');
 const auth=JSON.parse(await readFile(process.env.CAPHE_TEST_AUTH_FILE,'utf8'));
 const browser=await chromium.launch({headless:true});
 try{
  const page=await browser.newPage();let release,notify;
  const gate=new Promise(resolve=>release=resolve),requested=new Promise(resolve=>notify=resolve);
  await page.route('**/api/v1/jobs/*/bundle',async route=>{notify();await gate;await route.continue()});
  await page.goto(url);await page.getByRole('button',{name:'Connect API',exact:true}).click();
  await page.getByLabel('Tenant bearer token').fill(auth.tokens[0].token);await page.getByRole('button',{name:'Connect cluster',exact:true}).click();
  await requested;
  await page.getByRole('button',{name:'Settings',exact:true}).click();await page.getByRole('button',{name:'Disconnect',exact:true}).click();
  const verified=page.waitForResponse(r=>r.url().endsWith('/local/import'));release();await verified;
  await page.getByRole('button',{name:'Overview',exact:true}).click();
  await expect(page.getByText('SAMPLE DATA',{exact:true})).toBeVisible();
  await expect(page.locator('tr.finding')).toHaveCount(8);
  await expect(page.locator('tr[data-value="CP-0142"]')).toBeVisible();
 }finally{await browser.close()}
});
