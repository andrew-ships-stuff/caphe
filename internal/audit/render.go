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
	payload := base64.StdEncoding.EncodeToString(data)
	if err := auditHTML.Execute(w, payload); err != nil {
		return fmt.Errorf("render audit HTML: %w", err)
	}
	return nil
}

var auditHTML = template.Must(template.New("audit").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Caphe security posture</title><style>
:root{color-scheme:light dark;--bg:#f4f6f8;--panel:#fff;--text:#17212b;--muted:#667085;--line:#d8dee4;--accent:#1769aa}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}main{max-width:1200px;margin:auto;padding:32px 20px}h1{font-size:28px;margin:0}.sub,.muted{color:var(--muted)}.warning{background:#fff4e5;border:1px solid #f2b84b;color:#7a4d00;border-radius:10px;padding:12px 16px;margin-top:18px}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:24px 0}.metric,.finding,.toolbar,.empty,.posture{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}.metric strong{display:block;font-size:25px}.posture{margin-bottom:14px}.posture h2{margin-top:0}.recommendation{border-left:3px solid var(--accent);padding-left:12px;margin-top:12px}.toolbar{display:flex;gap:10px;flex-wrap:wrap;position:sticky;top:0;z-index:2}.toolbar input,.toolbar select{font:inherit;padding:9px 11px;border:1px solid var(--line);border-radius:7px;background:var(--panel);color:var(--text)}.toolbar input{flex:1;min-width:240px}.findings{display:grid;gap:12px;margin-top:14px}.finding h2{font-size:17px;margin:8px 0}.badge{display:inline-block;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:700;text-transform:uppercase;background:#e8edf2}.critical,.high{color:#b42318}.medium{color:#b54708}.low{color:#027a48}.meta{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.links a{margin-right:12px;color:var(--accent)}code{word-break:break-all}details{margin-top:10px}pre{white-space:pre-wrap;overflow:auto;font-size:12px}.empty{text-align:center;margin-top:14px}@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--panel:#161b22;--text:#e6edf3;--muted:#9da7b3;--line:#30363d;--accent:#58a6ff}.warning{background:#3b2b12;color:#ffd58a}}
</style></head><body><main><header><h1>Caphe security posture</h1><div class="sub" id="subtitle"></div><div class="warning" id="coverage" hidden></div></header><section class="summary" id="summary"></section><section class="posture" id="posture" hidden><h2>Repository posture <span class="badge">AI hypothesis · unverified</span></h2><p id="risk-summary"></p><ol id="priorities"></ol></section><section class="toolbar"><input id="search" type="search" placeholder="Search findings, rules, tools, or paths"><select id="severity"><option value="">All severities</option></select><select id="tool"><option value="">All tools</option></select></section><section class="findings" id="findings"></section><section class="empty" id="empty" hidden>No findings match these filters.</section></main>
<script id="caphe-bundle" type="application/octet-stream">{{.}}</script><script>
const bundle=JSON.parse(atob(document.getElementById('caphe-bundle').textContent.trim()));
const findings=bundle.findings||[], metrics=bundle.metrics||{}, tasks=bundle.tasks||[], recommendations=bundle.recommendations||[], severities=['critical','high','medium','low','info','unknown'];
const text=(tag,value,cls)=>{const e=document.createElement(tag);if(cls)e.className=cls;e.textContent=value;return e};
document.getElementById('subtitle').textContent=bundle.target+' · '+bundle.status+' · '+new Date(bundle.generatedAt).toLocaleString()+' · '+bundle.digest;
const succeeded=tasks.filter(t=>t.status==='succeeded').length, skipped=tasks.filter(t=>t.status==='skipped').map(t=>t.id);const summary=document.getElementById('summary');[['Findings',metrics.findings||0],['Critical',(metrics.bySeverity||{}).critical||0],['High',(metrics.bySeverity||{}).high||0],['Medium',(metrics.bySeverity||{}).medium||0],['Low',(metrics.bySeverity||{}).low||0],['Task coverage',succeeded+'/'+tasks.length]].forEach(([label,value])=>{const e=text('div','', 'metric');e.append(text('strong',String(value)),text('span',label,'muted'));summary.append(e)});if(skipped.length){const coverage=document.getElementById('coverage');coverage.hidden=false;coverage.textContent='Coverage warning: skipped tasks: '+skipped.join(', ')+'. Zero findings does not mean a clean target when scanners were skipped.'}
if(bundle.synthesis){document.getElementById('posture').hidden=false;document.getElementById('risk-summary').textContent=bundle.synthesis.riskSummary;(bundle.synthesis.priorities||[]).sort((a,b)=>a.rank-b.rank).forEach(p=>document.getElementById('priorities').append(text('li',p.title+' — '+p.rationale)))}
const sev=document.getElementById('severity'),tool=document.getElementById('tool');severities.filter(s=>findings.some(f=>f.severity===s)).forEach(s=>sev.add(new Option(s[0].toUpperCase()+s.slice(1),s)));[...new Set(findings.map(f=>f.tool))].sort().forEach(t=>tool.add(new Option(t,t)));
function references(rule){const box=document.createElement('div');box.className='links';const cves=String(rule).match(/CVE-\d{4}-\d{4,}/gi)||[];[...new Set(cves.map(x=>x.toUpperCase()))].forEach(id=>{const a=text('a',id+' on NVD');a.href='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(id);a.target='_blank';a.rel='noopener noreferrer';box.append(a)});const cwes=String(rule).match(/CWE-\d+/gi)||[];[...new Set(cwes.map(x=>x.toUpperCase()))].forEach(id=>{const a=text('a',id+' guidance');a.href='https://cwe.mitre.org/data/definitions/'+id.slice(4)+'.html';a.target='_blank';a.rel='noopener noreferrer';box.append(a)});return box}
function render(){const q=document.getElementById('search').value.toLowerCase(),s=sev.value,t=tool.value,root=document.getElementById('findings');root.replaceChildren();const visible=findings.filter(f=>{const hay=[f.title,f.ruleId,f.tool,f.description,f.location&&f.location.path].join(' ').toLowerCase();return(!q||hay.includes(q))&&(!s||f.severity===s)&&(!t||f.tool===t)});visible.forEach(f=>{const card=text('article','', 'finding');const meta=text('div','', 'meta');meta.append(text('span',f.severity||'unknown','badge '+(f.severity||'unknown')),text('span',f.tool,'muted'),text('code',f.ruleId||''));card.append(meta,text('h2',f.title||f.ruleId));if(f.description)card.append(text('p',f.description));if(f.location&&f.location.path)card.append(text('p',f.location.path+(f.location.startLine?':'+f.location.startLine:''),'muted'));const refs=references(f.ruleId);if(refs.childNodes.length)card.append(refs);const rec=recommendations.find(r=>r.findingId===f.id);if(rec){const box=text('div','', 'recommendation'),label=rec.status==='hypothesis'?'AI recommendation · hypothesis · unverified':'Evidence-backed recommendation';box.append(text('strong',label),text('p',rec.explanation),text('p','Remediation: '+rec.remediation));card.append(box)}const details=document.createElement('details'),summary=text('summary','Evidence details'),pre=text('pre',JSON.stringify({id:f.id,artifactDigest:f.artifactDigest,properties:f.properties},null,2));details.append(summary,pre);card.append(details);root.append(card)});document.getElementById('empty').hidden=visible.length!==0}
document.getElementById('search').addEventListener('input',render);sev.addEventListener('change',render);tool.addEventListener('change',render);render();
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
