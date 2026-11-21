import {test} from 'node:test';
import assert from 'node:assert/strict';
import {filterFindings,normalizeBundle,csv,escapeHTML} from '../../internal/workbench/web/model.mjs';
import {samples} from '../../internal/workbench/web/data.mjs';
test('filters compose, sorting is deterministic and resolved items stay out of fix queue',()=>{
 assert.equal(filterFindings(samples,{query:'24790',severity:'critical',repo:'edge-gateway'})[0].id,'CP-0142');
 assert.equal(filterFindings(samples,{query:'24790',severity:'low'}).length,0);
 assert.ok(filterFindings(samples,{queue:'fixable'}).every(f=>f.fixed&&f.state!=='Resolved'));
 assert.ok(filterFindings(samples,{queue:'exploitable'}).every(f=>f.reach==='Confirmed route'));
 assert.deepEqual(filterFindings(samples).map(f=>f.id),filterFindings([...samples].reverse()).map(f=>f.id));
});
test('live evidence never inherits sample reachability, CVSS or AI certainty',()=>{
 const f={id:'finding-a',fingerprint:'a',ruleId:'CVE-test',severity:'high',title:'Test',properties:{artifact:{name:'package',version:'1'},vulnerability:{fix:{versions:['2']}}}};
 const b={target:'repository',generatedAt:'2026-11-20',findings:[f],recommendations:[{findingId:f.id,source:'ai',status:'confirmed',explanation:'Do not promote'}]};
 const [view]=normalizeBundle(b);assert.equal(view.reach,'Not established');assert.equal(view.hypothesis,undefined);assert.equal(view.cvss,null);assert.equal(view.change,'uncompared');assert.equal(view.fixed,'2');
 const compared=normalizeBundle({...b,findings:[]},b);assert.equal(compared[0].change,'resolved');assert.equal(compared[0].state,'Resolved');
});
test('HTML is escaped and CSV formulas are neutralized',()=>{assert.equal(escapeHTML('<img onerror="x">'),'&lt;img onerror=&quot;x&quot;&gt;');assert.ok(csv([{title:'=cmd()',cve:'A',severity:'low'}]).includes('"\'=cmd()"'))});
