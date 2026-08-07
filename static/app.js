(function () {
  const $ = (s) => document.querySelector(s);
  const drop = $("#drop"), fileInput = $("#file"), browse = $("#browse"),
        analyzeBtn = $("#analyze"), filenameEl = $("#filename"),
        statusEl = $("#status"), resultsEl = $("#results");
  let chosen = null;

  // ---- file selection ----
  browse.addEventListener("click", (e) => { e.preventDefault(); fileInput.click(); });
  drop.addEventListener("click", (e) => { if (e.target.id !== "browse") fileInput.click(); });
  fileInput.addEventListener("change", () => setFile(fileInput.files[0]));
  ["dragover", "dragenter"].forEach(ev =>
    drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("drag"); }));
  ["dragleave", "drop"].forEach(ev =>
    drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("drag"); }));
  drop.addEventListener("drop", e => { if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]); });

  function setFile(f) {
    if (!f) return;
    chosen = f;
    filenameEl.textContent = `${f.name}  (${fmtSize(f.size)})`;
    analyzeBtn.disabled = false;
  }

  analyzeBtn.addEventListener("click", analyze);

  async function analyze() {
    if (!chosen) return;
    analyzeBtn.disabled = true;
    resultsEl.classList.add("hidden");
    resultsEl.innerHTML = "";
    showStatus(`<span class="spinner"></span>Analyzing <code>${esc(chosen.name)}</code> — unpacking, scanning dex/Mach-O, matching signatures…`, false);
    const fd = new FormData();
    fd.append("file", chosen);
    try {
      const res = await fetch("/api/analyze", { method: "POST", body: fd });
      const data = await res.json();
      if (!data.ok) { showStatus("❌ " + esc(data.error || "Analysis failed."), true); analyzeBtn.disabled = false; return; }
      statusEl.classList.add("hidden");
      render(data);
    } catch (err) {
      showStatus("❌ Request failed: " + esc(String(err)), true);
    }
    analyzeBtn.disabled = false;
  }

  function showStatus(html, isErr) {
    statusEl.className = "status" + (isErr ? " err" : "");
    statusEl.innerHTML = html;
  }

  // ---- rendering ----
  function render(d) {
    if (d.kind === "datadir") return renderDataDir(d);
    const m = d.meta || {};
    const isApk = d.file.type === "apk";
    const metaRows = isApk ? [
      ["Package", m.package], ["Version", m.version_name],
      ["min / target SDK", `${m.min_sdk ?? "?"} / ${m.target_sdk ?? "?"}`],
      ["Debuggable", m.debuggable === null ? "?" : String(m.debuggable)],
      ["Permissions", m.permissions_count],
    ] : [
      ["Bundle ID", m.bundle_id], ["Version", m.version],
      ["Min iOS", m.min_os], ["Executable", m.executable],
      ["Encrypted (FairPlay)", m.encrypted === null ? "unknown" : String(m.encrypted)],
      ["Arch", m.arch],
    ];

    const pills = [];
    pills.push(d.root.implemented
      ? `<span class="pill root">Root/JB · ${d.root.layers} layer${d.root.layers>1?"s":""}</span>`
      : `<span class="pill none">No root/JB detection</span>`);
    pills.push(d.ssl.implemented
      ? `<span class="pill ssl">SSL pinning · ${d.ssl.layers} layer${d.ssl.layers>1?"s":""}</span>`
      : `<span class="pill none">No SSL pinning</span>`);

    let html = `
    <div class="summary">
      <div class="card">
        <h2>${isApk ? "APK" : "IPA"} · ${esc(d.file.name)}</h2>
        ${metaRows.map(([k,v]) => `<div class="metaline"><span class="k">${esc(k)}</span><span class="v">${esc(v==null?"—":String(v))}</span></div>`).join("")}
        <div class="metaline"><span class="k">SHA-256</span><span class="v" style="font-size:11px">${esc(d.file.sha256)}</span></div>
      </div>
      <div class="card">
        <h2>Protection strength</h2>
        <div class="gauge">
          <div class="ring" style="--v:${d.score}"><b>${d.score}</b></div>
          <div>
            <div class="rating">${esc(d.rating)}</div>
            <div class="rlabel">heuristic score / 100</div>
            <div class="pillrow">${pills.join("")}</div>
          </div>
        </div>
        ${signingMini(d.signing)}
      </div>
    </div>
    ${exportBar()}`;

    // framework notes
    if (d.frameworks && d.frameworks.length) {
      html += `<div class="notes"><h3>App framework</h3><ul>` +
        d.frameworks.map(f => `<li><strong>${esc(f.name)}</strong>${f.note ? " — " + esc(f.note) : ""}</li>`).join("") +
        `</ul></div>`;
    }
    // analysis notes
    if (d.notes && d.notes.length) {
      html += `<div class="notes"><h3>Notes</h3><ul>` +
        d.notes.map(n => `<li>${esc(n)}</li>`).join("") + `</ul></div>`;
    }

    html += mechBlock("Root / Jailbreak detection", "root", d.root, isApk);
    html += mechBlock("SSL / Certificate pinning", "ssl", d.ssl, isApk);

    // MASVS extra findings
    html += masvsBlock(d.extra || []);

    // IPC attack surface (exported components + PoC)
    html += ipcBlock(d.ipc || []);

    // network attack surface (URLs / buckets / IPs)
    html += surfaceBlock(d.surface);

    // auto-generated Frida bypass script
    html += fridaBlock(d.frida);

    // guides
    if (d.guides && d.guides.length) {
      html += `<div class="block"><h2>🔓 Bypass playbooks (${d.guides.length})</h2>
        <p class="lead">Step-by-step guides for exactly the mechanisms found above. Expand each. Ordered easy → hard.</p>`;
      const order = { easy: 0, medium: 1, hard: 2 };
      const gs = d.guides.slice().sort((a,b) => (order[a.difficulty]??9)-(order[b.difficulty]??9));
      html += gs.map(renderGuide).join("");
      html += `</div>`;
    }

    html += `<p class="disclaimer">⚠️ Static analysis infers mechanisms from bytes/strings and can miss heavily
      obfuscated or server-side checks (and occasionally over-report shared library code). Confirm dynamically
      before drawing conclusions. Use only on apps you are authorized to test.</p>`;

    resultsEl.innerHTML = html;
    wireFrida(d.frida);
    wireIpc();
    wireExport(d);
    resultsEl.classList.remove("hidden");
    resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function signingMini(s) {
    if (!s || !s.schemes) return "";
    const scheme = (s.schemes.length ? s.schemes.join("+") : "unsigned");
    const key = s.key_algo ? `${String(s.key_algo).toUpperCase()} ${s.key_bits || "?"}-bit / ${s.hash_algo || "?"}` : "—";
    const flag = s.debug_cert ? ` <span class="badge sevb high">DEBUG CERT</span>` : "";
    return `<div class="signrow">
      <span>🔑 Signing: <b>${esc(scheme)}</b> · ${esc(key)}${flag}</span>
      ${s.subject ? `<div class="signsub">${esc(s.subject)}</div>` : ""}
    </div>`;
  }

  function ipcBlock(rows) {
    if (!rows || !rows.length) return "";
    const unprot = rows.filter(r => !r.protected).length;
    return `<div class="block"><h2>📡 IPC attack surface (${rows.length})</h2>
      <p class="lead">Exported components reachable by other apps — ${unprot} without a permission guard. Each has a ready adb PoC.</p>
      <div class="tablewrap"><table class="ipc">
        <thead><tr><th>Type</th><th>Component</th><th>Guard</th><th>PoC</th></tr></thead>
        <tbody>${rows.map(r => `<tr>
          <td><span class="tp tp-${esc(r.type)}">${esc(r.type)}</span></td>
          <td class="cn" title="${esc(r.fqn)}">${esc(r.name)}</td>
          <td>${r.protected ? `<span class="badge">perm</span>` : `<span class="badge sevb medium">none</span>`}</td>
          <td class="poc"><code>${esc(r.poc)}</code><button class="mini cpoc" data-poc="${esc(r.poc)}">copy</button></td>
        </tr>`).join("")}</tbody>
      </table></div></div>`;
  }

  function surfaceBlock(s) {
    if (!s) return "";
    const c = s.counts || {};
    const list = (title, items, total) => (items && items.length)
      ? `<details class="guide"><summary><span class="gtitle">${title} (${total})</span></summary>
          <div class="gbody"><pre class="frscript">${esc(items.join("\n"))}</pre></div></details>` : "";
    if (!(c.urls || c.buckets || c.ips)) return "";
    return `<div class="block"><h2>🌐 Network attack surface</h2>
      <p class="lead">URLs, cloud buckets and IPs harvested from the app — endpoints to probe (authorized scope only).</p>
      ${list("URLs / endpoints", s.urls, c.urls)}
      ${list("Cloud buckets (S3 / Firebase / GCS)", s.buckets, c.buckets)}
      ${list("IP addresses", s.ips, c.ips)}
    </div>`;
  }

  function exportBar() {
    return `<div class="exportbar">
      <span>Export report:</span>
      <button class="mini" id="exHtml">⬇ HTML</button>
      <button class="mini" id="exJson">⬇ JSON</button>
      <button class="mini" id="exSarif">⬇ SARIF</button>
    </div>`;
  }

  function mechBlock(title, cls, bucket, isApk) {
    const label = cls === "root"
      ? (isApk ? "Root detection" : "Jailbreak detection")
      : "SSL pinning";
    let h = `<div class="block"><h2><span class="dot ${cls}"></span>${esc(title)}</h2>`;
    if (!bucket.implemented) {
      h += `<div class="empty">No ${esc(label.toLowerCase())} detected by static signatures.
        ${cls==="ssl" ? "Traffic may be interceptable with just a proxy + trusted CA." :
          "The app likely runs fine on rooted/jailbroken devices without extra work."}</div></div>`;
      return h;
    }
    h += `<p class="lead">${bucket.layers} independent layer${bucket.layers>1?"s":""} detected.</p>`;
    h += bucket.mechanisms.map(mech => {
      const evid = mech.evidence ? `<div class="evid">Matched: <code>${esc(mech.evidence)}</code></div>` : "";
      const snip = mech.config_snippet ? `<div class="evid" style="margin-top:6px">Config:<br><code style="white-space:pre-wrap;display:block;margin-top:4px">${esc(mech.config_snippet)}</code></div>` : "";
      const ex = [];
      if (mech.verified === true) ex.push('<span class="badge verified">✓ verified</span>');
      if (mech.signals >= 2) ex.push(`<span class="badge">${mech.signals} signals</span>`);
      if (mech.corroborated) ex.push('<span class="badge">corroborated</span>');
      if (mech.unverified) ex.push('<span class="badge low">unverified</span>');
      return `<div class="mech l-${esc(mech.layer)}">
        <div class="mhead">
          <span class="mname">${esc(mech.name)}</span>
          <span class="badges">
            <span class="badge ${esc(mech.confidence)}">${esc(mech.confidence)}</span>
            <span class="badge layer">${esc(mech.layer)}</span>
            ${mech.masvs ? `<span class="badge masvs">${esc(mech.masvs)}</span>` : ""}
            ${ex.join("")}
          </span>
        </div>
        <div class="mdesc">${esc(mech.desc)}</div>
        ${evid}${snip}
      </div>`;
    }).join("");
    return h + `</div>`;
  }

  function renderDataDir(d) {
    const c = d.counts || {};
    const rows = [
      ["Files scanned", c.total_files], ["shared_prefs", c.prefs],
      ["databases", c.databases], ["other files", c.other_files],
      ["Findings", (d.findings || []).length],
    ];
    let html = `<div class="summary">
      <div class="card">
        <h2>Extracted data · ${esc(d.file.name)}</h2>
        ${rows.map(([k,v]) => `<div class="metaline"><span class="k">${esc(k)}</span><span class="v">${esc(v==null?"—":String(v))}</span></div>`).join("")}
        <div class="metaline"><span class="k">SHA-256</span><span class="v" style="font-size:11px">${esc(d.file.sha256)}</span></div>
      </div>
      <div class="card">
        <h2>Offline data-dir scan</h2>
        <p style="color:var(--muted);font-size:13.5px;margin:0 0 8px">This is a fully offline scan of an app's <em>runtime</em> data that you pulled yourself (adb backup / run-as / rooted copy).</p>
        <div class="pillrow">
          <span class="pill ${(d.findings||[]).some(f=>f.severity==='high')?'root':'none'}">${(d.findings||[]).filter(f=>f.severity==='high').length} high</span>
          <span class="pill none">${(d.findings||[]).filter(f=>f.severity==='medium').length} medium</span>
        </div>
      </div>
    </div>`;

    const items = d.findings || [];
    if (items.length) {
      html += `<div class="block"><h2>🗄️ Findings in extracted data (${items.length})</h2>
        <p class="lead">Cleartext secrets / PII found in shared_prefs and local databases.</p>` +
        items.map(f => renderFinding(f, f.severity === "high" ? "open" : "")).join("") + `</div>`;
    } else {
      html += `<div class="empty">No cleartext secrets or PII found in the extracted data. 👍</div>`;
    }
    html += `<p class="disclaimer">⚠️ Offline scan of data you provided. Absence of findings isn't proof of safety — coverage depends on what you pulled and whether stores are encrypted (SQLCipher DBs read as opaque). Authorized testing only.</p>`;
    resultsEl.innerHTML = html;
    resultsEl.classList.remove("hidden");
    resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
  function masvsBlock(items) {
    if (!items || !items.length) return "";
    const sorted = items.slice().sort((a, b) => (SEV_ORDER[a.severity]??9) - (SEV_ORDER[b.severity]??9));
    const openBig = sorted.length <= 4 ? "open" : "";
    return `<div class="block"><h2>🔎 Additional findings (${items.length})</h2>
      <p class="lead">Extra static checks (secrets, insecure config, weak crypto) — each with location, risk, repro &amp; fix. Not counted in the layer totals.</p>` +
      sorted.map(f => renderFinding(f, f.severity === "high" ? "open" : openBig)).join("") + `</div>`;
  }

  function renderFinding(f, open) {
    const steps = (f.reproduce || []).map(s => `<li>${fmtStep(s)}</li>`).join("");
    const ev = f.evidence ? `<div class="frow"><span class="fk">Evidence</span>
        <span class="fv"><pre class="fev">${esc(f.evidence)}</pre></span></div>` : "";
    const row = (k, v) => v ? `<div class="frow"><span class="fk">${k}</span><span class="fv">${v}</span></div>` : "";
    return `<details class="finding sev-${esc(f.severity)}" ${open}>
      <summary>
        <span class="fname">${esc(f.title)}</span>
        <span class="badges"><span class="badge sevb ${esc(f.severity)}">${esc(f.severity)}</span>
        <span class="badge layer">${esc(f.category)}</span>
        ${f.masvs ? `<span class="badge masvs">${esc(f.masvs)}</span>` : ""}</span>
      </summary>
      <div class="fbody">
        ${row("Location", f.location ? `<code>${esc(f.location)}</code>` : "")}
        ${ev}
        ${row("Description", esc(f.description || ""))}
        ${row("Risk", esc(f.risk || ""))}
        ${steps ? `<div class="frow"><span class="fk">Steps to reproduce</span><span class="fv"><ol class="steps">${steps}</ol></span></div>` : ""}
        ${row("Mitigation", esc(f.mitigation || ""))}
      </div>
    </details>`;
  }

  function fridaBlock(fr) {
    if (!fr || !fr.script) return "";
    const warn = (fr.warnings && fr.warnings.length)
      ? `<div class="frwarn">⚠️ ${fr.warnings.map(esc).join("<br>⚠️ ")}</div>` : "";
    return `<div class="block"><h2>⚡ Auto-generated Frida bypass</h2>
      <p class="lead">One script wired to <em>only</em> the mechanisms found above — covers: ${fr.hooks.map(esc).join(", ")}.</p>
      ${warn}
      <div class="frcmd"><code>${esc(fr.command)}</code>
        <button class="mini" id="copycmd">copy</button></div>
      <div class="frbar">
        <button class="mini" id="dlfrida">⬇ Download shieldscope_bypass.js</button>
        <button class="mini" id="copyfrida">Copy script</button>
      </div>
      <pre class="frscript" id="frscript">${esc(fr.script)}</pre>
    </div>`;
  }

  function wireFrida(fr) {
    if (!fr || !fr.script) return;
    const dl = $("#dlfrida"), cf = $("#copyfrida"), cc = $("#copycmd");
    if (dl) dl.onclick = () => {
      const blob = new Blob([fr.script], { type: "application/javascript" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = fr.filename || "shieldscope_bypass.js";
      a.click(); URL.revokeObjectURL(a.href);
    };
    if (cf) cf.onclick = () => copy(fr.script, cf);
    if (cc) cc.onclick = () => copy(fr.command, cc);
  }
  function copy(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
      const t = btn.textContent; btn.textContent = "✓ copied";
      setTimeout(() => btn.textContent = t, 1200);
    });
  }

  function wireIpc() {
    document.querySelectorAll(".cpoc").forEach(b => b.onclick = () => copy(b.dataset.poc, b));
  }

  // ---- report export (fully client-side / offline) ----
  function download(name, text, mime) {
    const blob = new Blob([text], { type: mime });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = name; a.click();
    URL.revokeObjectURL(a.href);
  }
  function baseName(d) {
    return "shieldscope_" + (d.file && d.file.name ? d.file.name.replace(/\.[^.]+$/, "") : "report");
  }
  function wireExport(d) {
    const j = $("#exJson"), s = $("#exSarif"), h = $("#exHtml");
    if (j) j.onclick = () => download(baseName(d) + ".json", JSON.stringify(d, null, 2), "application/json");
    if (s) s.onclick = () => download(baseName(d) + ".sarif", JSON.stringify(buildSarif(d), null, 2), "application/json");
    if (h) h.onclick = () => download(baseName(d) + ".html", buildHtmlReport(d), "text/html");
  }

  function allFindings(d) {
    let f = (d.extra || []).concat(d.findings || []);
    (d.root && d.root.mechanisms || []).forEach(m => f.push(mechAsFinding(m, "root")));
    (d.ssl && d.ssl.mechanisms || []).forEach(m => f.push(mechAsFinding(m, "ssl")));
    return f;
  }
  function mechAsFinding(m, kind) {
    return { id: (kind + "-" + m.id), title: (kind === "root" ? "Root/JB: " : "SSL pinning: ") + m.name,
      severity: "info", category: kind, masvs: m.masvs, location: m.evidence || "",
      description: m.desc, risk: "", reproduce: [], mitigation: "" };
  }
  const SEV2SARIF = { high: "error", medium: "warning", low: "note", info: "none" };
  function buildSarif(d) {
    const fs = allFindings(d);
    const rules = {}, results = [];
    fs.forEach(f => {
      rules[f.id] = rules[f.id] || { id: f.id, name: f.title,
        shortDescription: { text: f.title },
        properties: { category: f.category, masvs: f.masvs || "" } };
      results.push({
        ruleId: f.id, level: SEV2SARIF[f.severity] || "note",
        message: { text: (f.description || f.title) + (f.risk ? "\nRisk: " + f.risk : "") },
        locations: [{ physicalLocation: { artifactLocation: { uri: (f.location || "app").toString() } } }],
        properties: { severity: f.severity, masvs: f.masvs || "", evidence: f.evidence || "" }
      });
    });
    return { $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0",
      runs: [{ tool: { driver: { name: "ShieldScope", informationUri: "https://owasp.org/mas/",
        version: "1.0", rules: Object.values(rules) } }, results }] };
  }

  function buildHtmlReport(d) {
    const m = d.meta || {}, s = d.signing || {};
    const fs = (d.extra || []).concat(d.findings || []);
    const sevCount = k => fs.filter(f => f.severity === k).length;
    const row = (k, v) => v == null ? "" : `<tr><td>${esc(k)}</td><td>${esc(String(v))}</td></tr>`;
    const fCard = f => `<div class="f sev-${esc(f.severity)}">
      <h3>${esc(f.title)} <span class="s">${esc(f.severity)}</span> ${f.masvs ? `<span class="mv">${esc(f.masvs)}</span>` : ""}</h3>
      ${f.location ? `<p><b>Location:</b> <code>${esc(f.location)}</code></p>` : ""}
      ${f.evidence ? `<p><b>Evidence:</b></p><pre>${esc(f.evidence)}</pre>` : ""}
      ${f.description ? `<p><b>Description:</b> ${esc(f.description)}</p>` : ""}
      ${f.risk ? `<p><b>Risk:</b> ${esc(f.risk)}</p>` : ""}
      ${(f.reproduce && f.reproduce.length) ? `<p><b>Steps:</b></p><ol>${f.reproduce.map(x => `<li>${esc(x)}</li>`).join("")}</ol>` : ""}
      ${f.mitigation ? `<p><b>Mitigation:</b> ${esc(f.mitigation)}</p>` : ""}
    </div>`;
    const mechRow = (m2, kind) => `<li>${esc(m2.name)} <span class="mv">${esc(m2.masvs || "")}</span> — <i>${esc(m2.confidence || "")}</i></li>`;
    const order = { high: 0, medium: 1, low: 2, info: 3 };
    const fsSorted = fs.slice().sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
    return `<!doctype html><html><head><meta charset="utf-8"><title>ShieldScope report — ${esc(d.file.name)}</title>
<style>body{font:14px/1.55 -apple-system,Segoe UI,Roboto,Arial;margin:0;color:#1a2330;background:#fff}
header{background:#0b1220;color:#fff;padding:22px 32px}header h1{margin:0;font-size:22px}
main{max-width:960px;margin:0 auto;padding:24px 20px 60px}
table{border-collapse:collapse;width:100%;margin:8px 0 20px}td{border:1px solid #e2e8f0;padding:6px 10px;vertical-align:top}
td:first-child{color:#64748b;width:190px}h2{border-bottom:2px solid #e2e8f0;padding-bottom:6px;margin-top:32px}
.f{border:1px solid #e2e8f0;border-left:5px solid #94a3b8;border-radius:8px;padding:10px 16px;margin:10px 0}
.f.sev-high{border-left-color:#dc2626}.f.sev-medium{border-left-color:#f97316}.f.sev-low{border-left-color:#eab308}.f.sev-info{border-left-color:#3b82f6}
.f h3{margin:4px 0 8px;font-size:15px}.s{font-size:11px;text-transform:uppercase;background:#334155;color:#fff;padding:2px 8px;border-radius:10px}
.mv{font-size:11px;background:#0d9488;color:#fff;padding:2px 8px;border-radius:10px}
pre{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:6px;padding:8px 10px;white-space:pre-wrap;word-break:break-all;font-size:12px}
code{background:#f1f5f9;padding:1px 5px;border-radius:4px}.kpi{display:inline-block;margin-right:16px;font-weight:700}
.disc{color:#64748b;font-size:12px;margin-top:30px;border-top:1px solid #e2e8f0;padding-top:12px}</style></head>
<body><header><h1>🛡️ ShieldScope report</h1><div>${esc(d.file.name)} · ${esc(d.file.sha256)}</div></header><main>
<p><span class="kpi" style="color:#dc2626">${sevCount("high")} high</span>
<span class="kpi" style="color:#f97316">${sevCount("medium")} medium</span>
<span class="kpi" style="color:#eab308">${sevCount("low")} low</span>
<span class="kpi">Score ${esc(d.score)} (${esc(d.rating)})</span></p>
<h2>Application</h2><table>
${row("Package / Bundle", m.package || m.bundle_id)}${row("Version", m.version_name || m.version)}
${row("min / target SDK", (m.min_sdk ?? "?") + " / " + (m.target_sdk ?? "?"))}
${row("Frameworks", (d.frameworks || []).map(f => f.name).join(", "))}
${row("Signing", s.schemes ? s.schemes.join("+") + (s.debug_cert ? " (DEBUG CERT!)" : "") : null)}
${row("Signer", s.subject)}${row("Key", s.key_algo ? (String(s.key_algo).toUpperCase() + " " + s.key_bits + "-bit / " + s.hash_algo) : null)}</table>
<h2>Hardening detected</h2>
<p><b>Root/JB detection:</b> ${d.root && d.root.implemented ? d.root.layers + " layer(s)" : "none"} ·
<b>SSL pinning:</b> ${d.ssl && d.ssl.implemented ? d.ssl.layers + " layer(s)" : "none"}</p>
<ul>${(d.root && d.root.mechanisms || []).map(x => mechRow(x, "root")).join("")}
${(d.ssl && d.ssl.mechanisms || []).map(x => mechRow(x, "ssl")).join("")}</ul>
<h2>Findings (${fs.length})</h2>${fsSorted.map(fCard).join("")}
${(d.ipc && d.ipc.length) ? `<h2>Exported IPC (${d.ipc.length})</h2><table><tr><td>Type</td><td>Component</td><td>PoC</td></tr>${d.ipc.map(r => `<tr><td>${esc(r.type)}</td><td>${esc(r.name)}${r.protected ? "" : " <b>[no perm]</b>"}</td><td><code>${esc(r.poc)}</code></td></tr>`).join("")}</table>` : ""}
<p class="disc">Generated by ShieldScope · offline static analysis · for authorized testing only. Static analysis can miss obfuscated/server-side logic and occasionally over-report.</p>
</main></body></html>`;
  }

  function renderGuide(g) {
    const needs = (g.needs||[]).map(n => `<span>${esc(n)}</span>`).join("");
    const steps = (g.steps||[]).map(s => `<li>${fmtStep(s)}</li>`).join("");
    const res = (g.resources||[]).map(r => `<a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.label)}</a>`).join("");
    return `<details class="guide">
      <summary><span class="gtitle">${esc(g.title)}</span><span class="diff ${esc(g.difficulty)}">${esc(g.difficulty)}</span></summary>
      <div class="gbody">
        ${needs ? `<h4>Prerequisites</h4><div class="needs">${needs}</div>` : ""}
        <h4>Steps</h4><ol class="steps">${steps}</ol>
        ${res ? `<h4>Resources</h4><div class="res">${res}</div>` : ""}
      </div>
    </details>`;
  }

  // wrap `backtick code` spans and preserve newlines within a step
  function fmtStep(s) {
    let out = esc(s).replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`);
    out = out.replace(/\n/g, "<br>");
    return out;
  }

  function fmtSize(b) {
    if (b < 1024) return b + " B";
    if (b < 1048576) return (b/1024).toFixed(1) + " KB";
    return (b/1048576).toFixed(1) + " MB";
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  // small public API — render a previously saved result JSON
  window.ShieldScope = { render };
})();
