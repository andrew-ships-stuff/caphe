export const severityOrder = {critical:0,high:1,medium:2,low:3,info:4,unknown:5};
export const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const text = (value,fallback='') => typeof value==='string'||typeof value==='number'?String(value):fallback;
export function filterFindings(items,{query='',severity='all',repo='all',queue='all',sort='priority'}={}) {
 const q=query.toLowerCase().trim();
 return items.filter(f=>(repo==='all'||f.repo===repo)&&(severity==='all'||f.severity===severity)&&(!q||[f.id,f.cve,f.title,f.package,f.path,f.repo,f.source,f.cwe].join(' ').toLowerCase().includes(q))&&((queue==='all'&&f.state!=='Resolved')||(queue==='new'&&f.change==='new')||(queue==='exploitable'&&f.reach==='Confirmed route')||(queue==='fixable'&&f.fixed&&f.state!=='Resolved')||(queue==='revalidate'&&f.change==='revalidate')||(queue==='resolved'&&f.change==='resolved'))).sort((a,b)=>sort==='recent'?String(b.first).localeCompare(String(a.first)):sort==='asset'?a.repo.localeCompare(b.repo):sort==='effort'?Number(a.effort!=='Small')-Number(b.effort!=='Small')||(severityOrder[a.severity]??5)-(severityOrder[b.severity]??5):(severityOrder[a.severity]??5)-(severityOrder[b.severity]??5)||Number(b.reach==='Confirmed route')-Number(a.reach==='Confirmed route')||Number(!!b.fixed)-Number(!!a.fixed)||a.id.localeCompare(b.id));
}
export function normalizeBundle(bundle, previous=null, repository='') {
 const old=new Map((previous?.findings||[]).map(f=>[f.fingerprint||f.id,f]));
 const current=new Set((bundle.findings||[]).map(f=>f.fingerprint||f.id));
 function normalize(f,resolved=false) {
  const p=f.properties||{}, art=p.artifact||p.package||{},v=p.vulnerability||{};
  const fixes=v.fix?.versions;
  const recommendation=(bundle.recommendations||[]).find(r=>r.findingId===f.id&&r.source==='ai'&&r.status==='hypothesis');
  return {id:text(f.id),fingerprint:text(f.fingerprint),cve:text(f.ruleId),title:text(f.title),severity:Object.hasOwn(severityOrder,f.severity)?f.severity:'unknown',repo:repository||text(bundle.target,'Imported repository'),package:text(art.name,text(f.category,'Source code')),version:text(art.version,'Not reported'),source:text(f.tool).replace(/^scanner\./,''),path:text(f.location?.path,'Not reported'),line:f.location?.startLine||0,cvss:v.cvss?.[0]?.metrics?.baseScore??null,cwe:text(v.cwes?.[0],'Not reported'),fixed:Array.isArray(fixes)&&fixes.length?fixes.map(x=>text(x)).join(', '):null,state:resolved?'Resolved':'Open',change:resolved?'resolved':previous?(old.has(f.fingerprint||f.id)?'existing':'new'):'uncompared',first:text(old.get(f.fingerprint||f.id)?.observedAt||f.observedAt||bundle.generatedAt).slice(0,10),reach:'Not established',effort:'Unestimated',summary:text(f.description,text(f.title)),chain:[repository||text(bundle.target,'Repository'),text(art.name,text(f.location?.path,'Source location not reported'))],hypothesis:recommendation?.explanation,remediation:recommendation?.remediation,raw:f,artifactDigest:f.artifactDigest,fixture:false,bundleDigest:bundle.digest};
 }
 return [...(bundle.findings||[]).map(f=>normalize(f)),...(previous?.findings||[]).filter(f=>!current.has(f.fingerprint||f.id)).map(f=>normalize(f,true))];
}
export function csv(items) {
 const cell=x=>'"'+String(x??'').replaceAll('"','""').replace(/^[=+@\-\t\r]/,"'$&")+'"';
 return [['ID','Title','Severity','Repository','Package','State','Source','Reachability'],...items.map(f=>[f.cve,f.title,f.severity,f.repo,f.package,f.state,f.source,f.reach])].map(row=>row.map(cell).join(',')).join('\r\n');
}
