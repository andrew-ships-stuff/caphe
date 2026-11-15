package audit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"strings"

	"github.com/andrew-ships-stuff/caphe/internal/reporting"
)

func WriteJSON(path string, bundle Bundle) error {
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func WriteSARIF(path string, bundle Bundle) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	sarifErr := reporting.SARIF(file, bundle.Findings)
	closeErr := file.Close()
	if sarifErr != nil {
		return sarifErr
	}
	return closeErr
}

func WriteMarkdown(path string, bundle Bundle) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	markdownErr := RenderMarkdown(file, bundle)
	closeErr := file.Close()
	if markdownErr != nil {
		return markdownErr
	}
	return closeErr
}

func ReadJSON(path string) (Bundle, error) {
	file, err := os.Open(path)
	if err != nil {
		return Bundle{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, fmt.Errorf("parse audit bundle: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Bundle{}, fmt.Errorf("parse audit bundle: trailing content")
	}
	if bundle.SchemaVersion != SchemaVersion {
		return Bundle{}, fmt.Errorf("unsupported audit bundle schema %q", bundle.SchemaVersion)
	}
	want := bundle.Digest
	if want == "" {
		return Bundle{}, fmt.Errorf("audit bundle digest is required")
	}
	if err := setDigest(&bundle); err != nil {
		return Bundle{}, err
	}
	if bundle.Digest != want {
		return Bundle{}, fmt.Errorf("audit bundle digest mismatch")
	}
	bundle.Digest = want
	return bundle, nil
}

func WriteHTML(path string, bundle Bundle) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	renderErr := RenderHTML(file, bundle)
	closeErr := file.Close()
	if renderErr != nil {
		return renderErr
	}
	return closeErr
}

func RenderHTML(w io.Writer, bundle Bundle) error {
	data, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	groups, note := buildRemediation(&bundle)
	if err := auditHTML.Execute(w, htmlData{Payload: base64.StdEncoding.EncodeToString(data), Groups: groups, Note: note, Dedup: bundle.Dedup}); err != nil {
		return fmt.Errorf("render audit HTML: %w", err)
	}
	return nil
}

var auditHTML = template.Must(template.New("audit").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Caphe security posture</title><style>
:root{color-scheme:dark;--bg:#0d1117;--panel:#161b22;--text:#e6edf3;--muted:#9da7b3;--line:#30363d;--accent:#58a6ff}:root[data-theme=light]{color-scheme:light;--bg:#f4f6f8;--panel:#fff;--text:#17212b;--muted:#667085;--line:#d8dee4;--accent:#1769aa}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}main{max-width:1200px;margin:auto;padding:32px 20px}h1{font-size:28px;margin:0}.sub,.muted{color:var(--muted)}.warning{background:#3b2b12;border:1px solid #f2b84b;color:#ffd58a;border-radius:10px;padding:12px 16px;margin-top:18px}:root[data-theme=light] .warning{background:#fff4e5;color:#7a4d00}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:24px 0}.metric,.toolbar,.empty,.posture{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}.metric strong{display:block;font-size:25px}.posture{margin-bottom:14px}.posture h2{margin-top:0}.recommendation{border-left:3px solid var(--accent);padding-left:12px;margin-top:12px}.toolbar{display:flex;gap:10px;flex-wrap:wrap;position:sticky;top:0;z-index:2}.toolbar input,.toolbar select{font:inherit;padding:9px 11px;border:1px solid var(--line);border-radius:7px;background:var(--panel);color:var(--text)}.toolbar input{flex:1;min-width:240px}.findings{margin-top:14px;overflow-x:auto}.desc{font-size:12px;margin-top:2px}td pre{max-height:140px;overflow:auto;font-size:12px;max-width:360px}.badge{display:inline-block;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:700;text-transform:uppercase;background:#21262d;color:var(--text)}.badge.critical,.badge.high{color:#f85149;background:#3d1d20}.badge.medium{color:#d29922;background:#3a2d12}.badge.low{color:#3fb950;background:#12261e}.badge.info,.badge.unknown{color:#8b949e;background:#21262d}:root[data-theme=light] .badge{background:#e8edf2;color:#17212b}:root[data-theme=light] .badge.critical,:root[data-theme=light] .badge.high{color:#b42318;background:#ffebe9}:root[data-theme=light] .badge.medium{color:#b54708;background:#fff4e5}:root[data-theme=light] .badge.low{color:#027a48;background:#e6f4ea}.meta{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.links a{margin-right:12px;color:var(--accent)}code{word-break:break-all}details{margin-top:10px}pre{white-space:pre-wrap;overflow:auto;font-size:12px}.empty{text-align:center;margin-top:14px}button{font:inherit;padding:8px 12px;border:1px solid var(--line);border-radius:7px;background:var(--panel);color:var(--text);cursor:pointer;appearance:none;-webkit-appearance:none}button:hover{border-color:var(--accent)}button[disabled]{opacity:.5;cursor:default}select{appearance:none;-webkit-appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%238b949e'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;padding-right:30px}button:focus-visible,select:focus-visible,input:focus-visible{outline:2px solid var(--accent);outline-offset:1px}.expand-adv{padding:3px 8px;font-size:12px}.headrow{display:flex;justify-content:space-between;align-items:start;gap:12px}#tabs{display:flex;gap:8px;margin:20px 0 0}#tabs button.active{color:var(--accent);border-color:var(--accent);border-bottom-color:var(--bg);font-weight:700}.metric.clickable{cursor:pointer}.metric.clickable:hover{border-color:var(--accent)}.col-filter{flex:0 1 170px;min-width:130px}#csv{white-space:nowrap}table.plan{width:100%;border-collapse:collapse;margin-top:8px}table.plan th,table.plan td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}table.plan th{font-size:12px;text-transform:uppercase;color:var(--muted)}.plan-actions{margin:6px 0 12px}.pager{display:flex;gap:10px;align-items:center;margin-top:14px}.tools{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}.tool{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;cursor:pointer;text-align:left}.tool:hover{border-color:var(--accent)}.tool.active{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}.tool strong{display:block}.dots{display:flex;gap:4px;margin-top:6px}.dot{width:9px;height:9px;border-radius:50%;display:inline-block}.dot.critical,.dot.high{background:#f85149}.dot.medium{background:#d29922}.dot.low{background:#3fb950}.dot.info,.dot.unknown{background:#8b949e}
</style></head><body><main><header><div class="headrow"><h1>Caphe security posture</h1><button id="theme" title="Toggle color theme">Theme</button></div><div class="sub" id="subtitle"></div><div class="warning" id="coverage" hidden></div></header><section class="summary" id="summary"></section><section id="tools-section" hidden><h2>Tools</h2><div class="tools" id="tools"></div><p class="muted" id="pipeline" hidden></p></section><nav id="tabs"><button data-tab="plan" class="active">Remediation plan</button><button data-tab="findings">All findings</button></nav><div id="tab-plan"><section class="posture" id="remediation" {{if not .Groups}}hidden{{end}}><h2>Remediation plan <span class="badge">deterministic dedup</span></h2><p class="muted">{{.Note}}</p><div class="plan-actions"><button id="copy-all">Copy all remediation prompts</button></div><table class="plan"><thead><tr><th>Severity</th><th>Package / finding</th><th>Installed → fixed</th><th>Advisories</th><th></th></tr></thead><tbody>{{range .Groups}}<tr><td><span class="badge {{.Severity}}">{{.Severity}}</span></td><td>{{if eq .Kind "package"}}<code>{{.Package}}</code>{{if .Ecosystem}} <span class="muted">{{.Ecosystem}}</span>{{end}}{{else}}{{.Title}} <span class="muted">{{.Tool}}{{if .RuleURL}} · <a href="{{.RuleURL}}" target="_blank" rel="noopener noreferrer">{{.RuleID}}</a>{{else}}{{if .RuleID}} · {{.RuleID}}{{end}}{{end}}</span>{{end}}</td><td>{{if eq .Kind "package"}}<code>{{.InstalledVersion}}</code> → {{if .FixedPreview}}<code>{{.FixedPreview}}</code>{{else}}<span class="muted">no fix published</span>{{end}}{{else}}<span class="muted">{{.Location}}</span>{{end}}</td><td>{{if .AdvisoryCount}}{{.AdvisoryCount}} advisories{{if .CVECount}} · {{.CVECount}} CVEs{{end}}<br>{{range $i, $l := .AdvisoryLinks}}{{if $l.URL}}<a href="{{$l.URL}}" target="_blank" rel="noopener noreferrer"{{if ge $i 6}} class="adv-more" hidden{{end}}>{{$l.ID}}</a>{{else}}<span{{if ge $i 6}} class="adv-more" hidden{{end}}>{{$l.ID}}</span>{{end}} {{end}}{{if gt .MoreCount 0}}<button class="expand-adv" data-group="{{.ID}}">(+{{.MoreCount}} more)</button>{{end}}{{else}}<span class="muted">—</span>{{end}}</td><td><button class="copy" data-group="{{.ID}}">Copy prompt</button></td></tr>{{end}}</tbody></table>{{if .Dedup}}<p class="muted">AI dedup suggestions <span class="badge">hypothesis · unverified</span> — deterministic groups are authoritative; proposals below are advisory and never merged automatically.</p><ul id="dedup">{{range .Dedup}}<li><code>{{.GroupID}}</code> may duplicate <code>{{.DuplicateOf}}</code> — {{.Rationale}}</li>{{end}}</ul>{{end}}</section><section class="posture" id="posture" hidden><h2>Repository posture <span class="badge">AI hypothesis · unverified</span></h2><p id="risk-summary"></p><ol id="priorities"></ol></section></div><div id="tab-findings" hidden><section class="toolbar"><input id="search" type="search" placeholder="Search findings, rules, tools, or paths"><select id="severity"><option value="">All severities</option></select><select id="tool"><option value="">All tools</option></select><input id="rule" type="search" placeholder="Filter rule IDs" class="col-filter"><input id="path" type="search" placeholder="Filter paths" class="col-filter"><select id="pagesize" title="Page size"><option value="25" selected>25 per page</option><option value="50">50 per page</option><option value="100">100 per page</option><option value="ALL">ALL</option></select><button id="csv">Download CSV</button></section><section class="findings" id="findings"></section><div class="pager" id="pager" hidden></div><section class="empty" id="empty" hidden>No findings match these filters.</section></div><div id="prompt-library" hidden>{{range .Groups}}<pre class="caphe-prompt" data-group="{{.ID}}" data-findings="{{range .FindingIDs}}{{.}} {{end}}">{{.Prompt}}</pre>{{end}}</div></main>
<div id="caphe-bundle" hidden>{{.Payload}}</div><script>
const bundle=JSON.parse(atob(document.getElementById('caphe-bundle').textContent.trim()));
const findings=bundle.findings||[], metrics=bundle.metrics||{}, tasks=bundle.tasks||[], recommendations=bundle.recommendations||[], severities=['critical','high','medium','low','info','unknown'];let page=1;
const text=(tag,value,cls)=>{const e=document.createElement(tag);if(cls)e.className=cls;e.textContent=value;return e};
document.getElementById('subtitle').textContent=bundle.target+' · '+bundle.status+' · '+new Date(bundle.generatedAt).toLocaleString()+' · '+bundle.digest;
const succeeded=tasks.filter(t=>t.status==='succeeded').length, skipped=tasks.filter(t=>t.status==='skipped').map(t=>t.id);const summary=document.getElementById('summary');[['Findings',metrics.findings||0],['Critical',(metrics.bySeverity||{}).critical||0,'critical'],['High',(metrics.bySeverity||{}).high||0,'high'],['Medium',(metrics.bySeverity||{}).medium||0,'medium'],['Low',(metrics.bySeverity||{}).low||0,'low'],['Task coverage',succeeded+'/'+tasks.length]].forEach(([label,value,sevKey])=>{const e=text('div','', 'metric');if(sevKey){e.classList.add('clickable');e.title='Filter findings by '+sevKey;e.onclick=()=>{sev.value=sevKey;page=1;switchTab('findings');render()}}e.append(text('strong',String(value)),text('span',label,'muted'));summary.append(e)});if(skipped.length){const coverage=document.getElementById('coverage');coverage.hidden=false;coverage.textContent='Coverage warning: skipped tasks: '+skipped.join(', ')+'. Zero findings does not mean a clean target when scanners were skipped.'}
if(bundle.synthesis){document.getElementById('posture').hidden=false;document.getElementById('risk-summary').textContent=bundle.synthesis.riskSummary;(bundle.synthesis.priorities||[]).sort((a,b)=>a.rank-b.rank).forEach(p=>document.getElementById('priorities').append(text('li',p.title+' — '+p.rationale)))}
const sev=document.getElementById('severity'),tool=document.getElementById('tool');severities.filter(s=>findings.some(f=>f.severity===s)).forEach(s=>sev.add(new Option(s[0].toUpperCase()+s.slice(1),s)));[...new Set(findings.map(f=>f.tool))].sort().forEach(t=>tool.add(new Option(t,t)));
function references(rule){const box=document.createElement('div');box.className='links';const cves=String(rule).match(/CVE-\d{4}-\d{4,}/gi)||[];[...new Set(cves.map(x=>x.toUpperCase()))].forEach(id=>{const a=text('a',id+' on NVD');a.href='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(id);a.target='_blank';a.rel='noopener noreferrer';box.append(a)});const ghsas=String(rule).match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4,}/gi)||[];[...new Set(ghsas.map(x=>x.toUpperCase()))].forEach(id=>{const a=text('a',id+' advisory');a.href='https://github.com/advisories/'+encodeURIComponent(id);a.target='_blank';a.rel='noopener noreferrer';box.append(a)});const cwes=String(rule).match(/CWE-\d+/gi)||[];[...new Set(cwes.map(x=>x.toUpperCase()))].forEach(id=>{const a=text('a',id+' guidance');a.href='https://cwe.mitre.org/data/definitions/'+id.slice(4)+'.html';a.target='_blank';a.rel='noopener noreferrer';box.append(a)});return box}
function visibleFindings(){const q=document.getElementById('search').value.toLowerCase(),s=sev.value,t=tool.value,r=document.getElementById('rule').value.toLowerCase(),p=document.getElementById('path').value.toLowerCase();return findings.filter(f=>{const hay=[f.title,f.ruleId,f.tool,f.description,f.location&&f.location.path].join(' ').toLowerCase();return(!q||hay.includes(q))&&(!s||f.severity===s)&&(!t||f.tool===t)&&(!r||String(f.ruleId||'').toLowerCase().includes(r))&&(!p||String((f.location&&f.location.path)||'').toLowerCase().includes(p))})}
function render(){const root=document.getElementById('findings');root.replaceChildren();const visible=visibleFindings();document.querySelectorAll('.tool[data-tool]').forEach(c=>c.classList.toggle('active',c.dataset.tool===tool.value));const size=document.getElementById('pagesize').value==='ALL'?Math.max(1,visible.length):Number(document.getElementById('pagesize').value)||25,pageCount=Math.max(1,Math.ceil(visible.length/size));if(page>pageCount)page=pageCount;const from=(page-1)*size;const cell=el=>{const td=text('td','');if(el!=null)td.append(typeof el==='string'?text('span',el):el);return td};
const table=text('table','','plan'),thead=text('thead',''),hrow=text('tr','');['Severity','Tool','Rule','Title','Location','Links','Evidence',''].forEach(h=>hrow.append(text('th',h)));thead.append(hrow);const body=text('tbody','');
visible.slice(from,from+size).forEach(f=>{const row=text('tr','');row.append(cell(text('span',f.severity||'unknown','badge '+(f.severity||'unknown'))),cell(text('span',f.tool,'muted')));
const rid=f.ruleId||'';let ruleEl=text('code',rid);if(f.tool==='scanner.opengrep'&&/^[A-Za-z0-9._-]+$/.test(rid)){const ruleLink=text('a','');ruleLink.append(ruleEl);ruleLink.href='https://semgrep.dev/r/'+encodeURIComponent(rid);ruleLink.target='_blank';ruleLink.rel='noopener noreferrer';ruleLink.title='Open this Opengrep rule in the rule registry';ruleEl=ruleLink}row.append(cell(ruleEl));
const titleBox=text('div','');titleBox.append(text('strong',f.title||f.ruleId||rid));if(f.description)titleBox.append(text('div',f.description,'muted desc'));row.append(cell(titleBox));
row.append(cell(text('span',(f.location&&f.location.path)?f.location.path+(f.location.startLine?':'+f.location.startLine:''):'','muted')));
const refs=references(f.ruleId);row.append(cell(refs.childNodes.length?refs:text('span','—','muted')));
const details=document.createElement('details');details.append(text('summary','JSON'),text('pre',JSON.stringify({id:f.id,artifactDigest:f.artifactDigest,properties:f.properties},null,2)));const rec=recommendations.find(r=>r.findingId===f.id);if(rec){const label=rec.status==='hypothesis'?'AI recommendation · hypothesis · unverified':'Evidence-backed recommendation';details.append(text('strong',label),text('p',rec.explanation),text('p','Remediation: '+rec.remediation))}row.append(cell(details));
const copy=text('button','Copy fix prompt','copy');copy.dataset.finding=f.id;row.append(cell(copy));body.append(row)});
table.append(thead,body);root.replaceChildren(table);const pager=document.getElementById('pager');pager.replaceChildren();if(visible.length){const prev=text('button','Prev');prev.disabled=page<=1;prev.onclick=()=>{if(page>1){page--;render()}};const next=text('button','Next');next.disabled=page>=pageCount;next.onclick=()=>{if(page<pageCount){page++;render()}};pager.append(prev,text('span','Page '+page+' of '+pageCount+' · showing '+(from+1)+'–'+Math.min(from+size,visible.length)+' of '+visible.length,'muted'),next)}pager.hidden=visible.length===0;document.getElementById('empty').hidden=visible.length!==0}
function switchTab(name){document.getElementById('tab-plan').hidden=name!=='plan';document.getElementById('tab-findings').hidden=name!=='findings';document.getElementById('tabs').querySelectorAll('button').forEach(b=>b.classList.toggle('active',b.dataset.tab===name))}
document.getElementById('tabs').addEventListener('click',e=>{const b=e.target.closest('button[data-tab]');if(b)switchTab(b.dataset.tab)});
const toolCounts={};findings.forEach(f=>{const c=toolCounts[f.tool]=toolCounts[f.tool]||{count:0,sev:{}};c.count++;c.sev[f.severity||'unknown']=(c.sev[f.severity||'unknown']||0)+1});
const taskByUses={},pipelineTasks=[];tasks.forEach(t=>{const u=String(t.uses||'');if(u.startsWith('scanner.')){(taskByUses[u]=taskByUses[u]||[]).push(t)}else pipelineTasks.push(t)});
const toolNames=[...new Set([...Object.keys(toolCounts),...Object.keys(taskByUses)])].sort();
if(toolNames.length||pipelineTasks.length){document.getElementById('tools-section').hidden=false;const grid=document.getElementById('tools');toolNames.forEach(name=>{const card=text('button','','tool');card.dataset.tool=name;const ts=taskByUses[name]||[];const count=toolCounts[name]?toolCounts[name].count:0;const status=ts.length?ts.map(t=>t.id+' · '+t.status).join(', '):'no task ran';card.append(text('strong',name),text('span',count+(count===1?' finding':' findings')+' · '+status,'muted'));const dots=text('span','','dots');severities.forEach(sv=>{for(let i=0;i<Math.min((toolCounts[name]&&toolCounts[name].sev[sv])||0,8);i++)dots.append(text('span','','dot '+sv))});card.append(dots);card.onclick=()=>{tool.value=tool.value===name?'':name;page=1;switchTab('findings');render()};grid.append(card)});if(pipelineTasks.length){const p=document.getElementById('pipeline');p.hidden=false;p.textContent='pipeline: '+pipelineTasks.map(t=>t.id+' · '+t.status).join(' · ')}}
const resetPage=()=>{page=1;render()};document.getElementById('search').addEventListener('input',resetPage);sev.addEventListener('change',resetPage);tool.addEventListener('change',resetPage);document.getElementById('pagesize').addEventListener('change',resetPage);document.getElementById('rule').addEventListener('input',resetPage);document.getElementById('path').addEventListener('input',resetPage);
document.getElementById('csv').addEventListener('click',()=>{const rows=[['id','severity','tool','ruleId','title','path','line','fingerprint']];visibleFindings().forEach(f=>rows.push([f.id,f.severity||'',f.tool||'',f.ruleId||'',f.title||'',(f.location&&f.location.path)||'',(f.location&&f.location.startLine)||'',f.fingerprint||'']));const csv=rows.map(r=>r.map(v=>'"'+String(v).replace(/"/g,'""')+'"').join(',')).join('\r\n');const blob=new Blob([csv],{type:'text/csv'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='caphe-findings.csv';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),2000)});
const themeBtn=document.getElementById('theme');try{const saved=localStorage.getItem('caphe-theme');if(saved)document.documentElement.dataset.theme=saved}catch(_){}
const syncThemeBtn=()=>{themeBtn.textContent=(document.documentElement.dataset.theme||'dark')==='dark'?'Light mode':'Dark mode'};themeBtn.onclick=()=>{document.documentElement.dataset.theme=(document.documentElement.dataset.theme||'dark')==='dark'?'light':'dark';try{localStorage.setItem('caphe-theme',document.documentElement.dataset.theme)}catch(_){}syncThemeBtn()};syncThemeBtn();
const promptBlocks=[...document.querySelectorAll('.caphe-prompt')];
function flash(btn,label){if(!btn)return;const old=btn.textContent;btn.textContent=label;btn.disabled=true;setTimeout(()=>{btn.textContent=old;btn.disabled=false},1400)}
function copyText(value,btn){if(!value){flash(btn,'No prompt');return false}
const area=document.createElement('textarea');area.value=value;area.setAttribute('readonly','');area.style.cssText='position:fixed;top:0;left:0;opacity:0';document.body.append(area);area.select();let ok=false;try{ok=document.execCommand('copy')}catch(_){ok=false}area.remove();
if(!ok&&navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(value).catch(()=>{});ok=true}
flash(btn,ok?'Copied!':'Copy failed');return ok}
document.getElementById('findings').addEventListener('click',e=>{const b=e.target.closest('button.copy');if(!b)return;const hit=promptBlocks.find(p=>(p.dataset.findings||'').split(/\s+/).includes(b.dataset.finding));copyText(hit?hit.textContent:'',b)});
document.getElementById('remediation').addEventListener('click',e=>{const exp=e.target.closest('button.expand-adv');if(exp){const cell=exp.closest('td');cell.querySelectorAll('.adv-more').forEach(a=>{a.hidden=false});exp.remove();return}const b=e.target.closest('button.copy');if(!b)return;const hit=promptBlocks.find(p=>p.dataset.group===b.dataset.group);copyText(hit?hit.textContent:'',b)});
document.getElementById('copy-all').addEventListener('click',e=>{const b=e.target;const all=promptBlocks.map(p=>p.textContent.trim()).join('\n\n---\n\n');if(all.length>50000){copyText('Caphe remediation set is too large to paste ('+promptBlocks.length+' prompts, '+all.length+' characters). The complete per-finding prompts are embedded in this caphe-audit.html file inside pre.caphe-prompt blocks: grep -n "caphe-prompt" caphe-audit.html, match each data-findings attribute to the finding IDs you need, and hand the matching prompt blocks to your coding agent.',b)}else copyText(all,b)});
render();
</script></body></html>`))

func RenderMarkdown(w io.Writer, bundle Bundle) error {
	fmt.Fprintf(w, "# Caphe security audit\n\n")
	fmt.Fprintf(w, "Target `%s` · workflow `%s` · execution `%s` · status **%s** · bundle `%s`\n\n", bundle.Target, bundle.Workflow, bundle.ExecutionID, bundle.Status, bundle.Digest)
	fmt.Fprintf(w, "| Findings | Critical | High | Medium | Low | Model calls |\n|---:|---:|---:|---:|---:|---:|\n")
	fmt.Fprintf(w, "| %d | %d | %d | %d | %d | %d |\n\n", bundle.Metrics.Findings, bundle.Metrics.BySeverity["critical"], bundle.Metrics.BySeverity["high"], bundle.Metrics.BySeverity["medium"], bundle.Metrics.BySeverity["low"], bundle.Metrics.ModelCalls)
	fmt.Fprintf(w, "Scanner tasks: ")
	for index, task := range bundle.Tasks {
		if index > 0 {
			fmt.Fprint(w, ", ")
		}
		fmt.Fprintf(w, "`%s` (%s)", task.ID, task.Status)
	}
	fmt.Fprint(w, "\n\n")
	if bundle.Synthesis != nil {
		fmt.Fprint(w, "## Repository posture (AI hypothesis, unverified)\n\n")
		fmt.Fprint(w, strings.ReplaceAll(strings.TrimSpace(bundle.Synthesis.RiskSummary), "\r", "")+"\n\n")
		if len(bundle.Synthesis.Priorities) > 0 {
			fmt.Fprint(w, "## Priorities (AI hypothesis, unverified)\n\n")
			for _, priority := range bundle.Synthesis.Priorities {
				fmt.Fprintf(w, "%d. **%s** — %s\n   Evidence: `%s`\n", priority.Rank, priority.Title, priority.Rationale, strings.Join(priority.EvidenceIDs, "`, `"))
			}
			fmt.Fprint(w, "\n")
		}
	}
	if len(bundle.Recommendations) > 0 {
		fmt.Fprint(w, "## Recommendations\n\n")
		for _, recommendation := range bundle.Recommendations {
			source := recommendation.Source
			if recommendation.Status == "hypothesis" {
				source = "AI hypothesis (unverified)"
			}
			fmt.Fprintf(w, "- `%s` (%s): %s\n  Remediation: %s\n", recommendation.FindingID, source, recommendation.Explanation, recommendation.Remediation)
		}
		fmt.Fprint(w, "\n")
	}
	if len(bundle.AI.Errors) > 0 {
		fmt.Fprint(w, "## AI notes\n\n")
		for _, message := range bundle.AI.Errors {
			fmt.Fprintf(w, "- %s\n", message)
		}
		fmt.Fprint(w, "\n")
	}
	fmt.Fprint(w, "AI text is advisory, never claims verification, and never determines policy.\n")
	return nil
}
