(function () {
  const $ = (s) => document.querySelector(s);
  const drop = $("#drop"), fileInput = $("#file"), browse = $("#browse"),
        analyzeBtn = $("#analyze"), filenameEl = $("#filename"),
        statusEl = $("#status"), resultsEl = $("#results");
  let chosen = null;

  // ---- file selection ----
  browse.addEventListener("click", (e) => { e.preventDefault(); fileInput.click(); });
  drop.addEventListener("click", (e) => { if (e.target.closest("button")) return; fileInput.click(); });
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
        ${engineMini(d)}
      </div>
    </div>
    ${exportBar()}
    <div class="aiplan"><button class="mini" id="aiPlan">🤖 AI pentest plan</button>
      <span class="aiplanhint">Uses your configured model to turn these findings into a prioritised attack plan.</span>
      <div id="aiPlanOut"></div></div>`;

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

    // API endpoints + per-endpoint pentest playbooks
    html += apiBlock(d.api);

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
    lastResult = d;
    wireAI(d);
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

  function engineMini(d) {
    const o = d.obfuscation, s = d.stats || {};
    if (!o && !s.files_scanned) return "";
    const bits = [];
    if (o) bits.push(`🧩 Obfuscation: <b>${esc(o.level)}</b> (${esc(String(o.ratio))})`);
    if (s.files_scanned) bits.push(`🔬 ${esc(String(s.files_scanned))} files scanned`);
    if (s.nested_archives) bits.push(`📦 ${esc(String(s.nested_archives))} nested archive(s)`);
    return `<div class="signrow" style="font-size:12.5px">${bits.join(" · ")}</div>`;
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

  function apiBlock(api) {
    if (!api || !api.endpoints || !api.endpoints.length) return "";
    const c = api.counts || {};
    const sens = api.endpoints.filter(e => (e.severity === "high" || e.severity === "medium") && e.category !== "third-party");
    const rest = api.endpoints.filter(e => !sens.includes(e));
    const card = e => {
      const steps = (e.tests || []).map(t => `<li>${fmtStep(t)}</li>`).join("");
      const extra = [];
      if (e.payload) extra.push(`<div class="frow"><span class="fk">Payload / technique</span><span class="fv"><code>${esc(e.payload)}</code></span></div>`);
      if (e.tool) extra.push(`<div class="frow"><span class="fk">Tool</span><span class="fv">${esc(e.tool)}</span></div>`);
      return `<details class="finding sev-${esc(e.severity)}">
        <summary>
          <span class="fname">${esc(e.value)}</span>
          <span class="badges"><span class="badge sevb ${esc(e.severity)}">${esc(e.severity)}</span>
          <span class="badge layer">${esc(e.category_name)}</span>
          <span class="badge">${esc(e.kind)}</span></span>
        </summary>
        <div class="fbody">
          <div class="frow"><span class="fk">Why it matters</span><span class="fv">${esc(e.why)}</span></div>
          ${steps ? `<div class="frow"><span class="fk">How to test</span><span class="fv"><ol class="steps">${steps}</ol></span></div>` : ""}
          ${extra.join("")}
        </div>
      </details>`;
    };
    let h = `<div class="block"><h2>🎯 API endpoints &amp; attack surface (${c.total || api.endpoints.length}${c.sensitive ? `, ${c.sensitive} sensitive` : ""})</h2>
      <p class="lead">Endpoints harvested from the app (URLs + relative API paths, including ones built from a base URL). Sensitive ones carry a test playbook. Static leads — verify with an intercepting proxy on an authorized target.</p>`;
    if (sens.length) h += sens.map(card).join("");
    if (rest.length) {
      const list = rest.map(e => `${e.severity === "info" ? "·" : "•"} [${esc(e.category_name)}] ${esc(e.value)}`).join("\n");
      h += `<details class="guide"><summary><span class="gtitle">Other endpoints &amp; third-party (${rest.length})</span></summary>
        <div class="gbody"><pre class="frscript">${esc(list)}</pre></div></details>`;
    }
    return h + `</div>`;
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
      <button class="mini" id="exBurp">⬇ Burp scope</button>
      <button class="mini" id="exTargets">⬇ Targets</button>
    </div>`;
  }

  // hosts from harvested endpoints + surface, for a proxy scope
  function collectHosts(d) {
    const hosts = new Set();
    const add = u => { try { const h = new URL(u).hostname; if (h) hosts.add(h); } catch (e) {} };
    ((d.api && d.api.endpoints) || []).forEach(e => { if (e.kind === "url") add(e.value); });
    ((d.surface && d.surface.urls) || []).forEach(add);
    return [...hosts].sort();
  }
  function buildBurpScope(d) {
    const esc = h => "^" + h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$";
    const include = collectHosts(d).map(h => ({ enabled: true, host: esc(h), protocol: "any" }));
    return { target: { scope: { advanced_mode: true, include, exclude: [] } } };
  }
  function buildTargets(d) {
    const lines = [];
    lines.push("# ShieldScope targets — " + (d.file ? d.file.name : "app") + " (authorized testing only)");
    const eps = (d.api && d.api.endpoints) || [];
    const sens = eps.filter(e => (e.severity === "high" || e.severity === "medium") && e.category !== "third-party");
    if (sens.length) { lines.push("\n## sensitive endpoints"); sens.forEach(e => lines.push(`[${e.category_name}] ${e.value}`)); }
    const urls = eps.filter(e => e.kind === "url" && e.category !== "third-party").map(e => e.value);
    if (urls.length) { lines.push("\n## api urls"); [...new Set(urls)].forEach(u => lines.push(u)); }
    const paths = eps.filter(e => e.kind === "path").map(e => e.value);
    if (paths.length) { lines.push("\n## relative paths (append to a base host)"); [...new Set(paths)].forEach(p => lines.push(p)); }
    lines.push("\n## hosts (scope)"); collectHosts(d).forEach(h => lines.push(h));
    return lines.join("\n");
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

  function jwtRow(j) {
    const issues = (j.issues || []).map(i => `<li>${esc(i)}</li>`).join("");
    const claims = esc(JSON.stringify(j.claims || {}, null, 1));
    const exp = j.expired === true ? "expired" : j.expired === false ? "not expired" : "no exp";
    return `<div class="frow"><span class="fk">JWT decoded</span><span class="fv">
      <div><span class="badge layer">alg ${esc(j.alg)}</span> <span class="badge layer">${esc(exp)}</span>
      ${(j.sensitive_claims||[]).length ? `<span class="badge medium">claims: ${esc(j.sensitive_claims.join(", "))}</span>` : ""}</div>
      ${issues ? `<ul class="steps" style="margin-top:6px">${issues}</ul>` : ""}
      <pre class="fev" style="margin-top:6px">${claims}</pre></span></div>`;
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
        ${f.jwt ? jwtRow(f.jwt) : ""}
        ${row("Description", esc(f.description || ""))}
        ${row("Risk", esc(f.risk || ""))}
        ${steps ? `<div class="frow"><span class="fk">Steps to reproduce</span><span class="fv"><ol class="steps">${steps}</ol></span></div>` : ""}
        ${row("Mitigation", esc(f.mitigation || ""))}
        <div class="ai-f"><button class="mini ai-analyze" data-fid="${esc(f.id)}">🤖 Analyze &amp; PoC</button><div class="ai-out"></div></div>
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
      <div class="fdyn ai-f">
        <h3>Dynamic — run &amp; AI bypass agent</h3>
        <p class="lead">Runs on a connected device/emulator (frida-server required). The AI agent writes its own scripts, runs them, and iterates — with Flutter-specific strategies.</p>
        <div class="frbar">
          <select id="fdevice"><option value="">(default USB)</option></select>
          <button class="mini" id="frunScript">▶ Run this script on device</button>
          <button class="mini" id="faiAgent">🤖 AI bypass agent</button>
        </div>
        <div id="fdynOut"></div>
      </div>
    </div>`;
  }

  function renderRun(o) {
    if (!o) return "";
    if (o.error && !o.iterations) return `<div class='aierr'>${esc(o.error)}</div>`;
    if (o.iterations) {
      const iters = o.iterations.map(it => {
        const con = (it.run.console || []).slice(0, 20).join("\n");
        return `<details class="guide"><summary><span class="gtitle">Iteration ${it.iter} — ${esc(it.verdict)}</span></summary>
          <div class="gbody">
            ${it.run.errors && it.run.errors.length ? `<div class='aierr'>${esc(it.run.errors.join("\n"))}</div>` : ""}
            <h4>Console</h4><pre class="frscript">${esc(con || "(none)")}</pre>
            <h4>Script</h4><pre class="frscript">${esc(it.script)}</pre>
          </div></details>`;
      }).join("");
      return `<div class="${o.confirmed ? "aiout" : "frwarn"}" style="margin:8px 0">
        ${o.confirmed ? "✓ hooks installed" : "· not confirmed yet"}${o.flutter ? " · Flutter mode" : ""}. ${esc(o.note || "")}</div>${iters}`;
    }
    // single run
    const con = (o.console || []).join("\n");
    return `<div class="${o.ok ? "aiout" : "frwarn"}" style="margin:8px 0">${o.ok ? "✓ loaded" : "· "+esc(o.error||"failed")}${(o.markers||[]).length ? " — "+esc(o.markers.join(" | ")) : ""}</div>
      ${con ? `<pre class="frscript">${esc(con)}</pre>` : ""}`;
  }

  function wireFrida(fr) {
    if (!fr || !fr.script) return;
    const dl = $("#dlfrida"), cf = $("#copyfrida"), cc = $("#copycmd");
    // dynamic: device list + run + AI agent
    const dev = $("#fdevice"), runBtn = $("#frunScript"), agent = $("#faiAgent"), out = $("#fdynOut");
    if (dev) fetch("/api/ai/frida/devices").then(r => r.json()).then(j => {
      (j.devices || []).forEach(d => { const o = document.createElement("option"); o.value = d.id; o.textContent = `${d.name} (${d.type})`; dev.appendChild(o); });
    }).catch(() => {});
    const pkg = () => (lastResult && lastResult.meta && lastResult.meta.package) || "";
    if (runBtn) runBtn.onclick = async () => {
      out.innerHTML = "<span class='spinner'></span> injecting…";
      try {
        const r = await (await fetch("/api/ai/frida/run", { method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ package: pkg(), script: fr.script, device_id: dev.value }) })).json();
        out.innerHTML = renderRun(r);
      } catch (e) { out.innerHTML = `<div class='aierr'>${esc(String(e))}</div>`; }
    };
    if (agent) agent.onclick = async () => {
      out.innerHTML = "<span class='spinner'></span> AI agent working (writing, running, refining)…";
      try {
        const r = await (await fetch("/api/ai/frida/bypass", { method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ result: lastResult, package: pkg(), goal: "ssl", device_id: dev.value }) })).json();
        out.innerHTML = r.enabled === false ? "<div class='aierr'>Configure an AI model above first.</div>" : renderRun(r);
      } catch (e) { out.innerHTML = `<div class='aierr'>${esc(String(e))}</div>`; }
    };
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
    const b = $("#exBurp"), t = $("#exTargets");
    if (b) b.onclick = () => download(baseName(d) + "_burp_scope.json", JSON.stringify(buildBurpScope(d), null, 2), "application/json");
    if (t) t.onclick = () => download(baseName(d) + "_targets.txt", buildTargets(d), "text/plain");
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

  // ===================================================================
  //  Optional AI assist (additive; deterministic engine is unaffected)
  // ===================================================================
  let lastResult = null, aiEnabled = false;

  async function initAI() {
    const prov = $("#aiProvider"), base = $("#aiBaseUrl"), model = $("#aiModel"),
          key = $("#aiKey"), save = $("#aiSave"), tmo = $("#aiTimeout");
    if (!prov) return;
    try {
      const s = await (await fetch("/api/ai/status")).json();
      const c = s.config || {};
      prov.value = c.provider || "off"; base.value = c.base_url || "";
      model.value = c.model || ""; if (c.api_key === "***set***") key.placeholder = "(saved)";
      if (tmo) tmo.value = c.timeout || "";
      setAiStatus(s);
    } catch (e) { /* AI layer optional */ }
    if (save) save.onclick = async () => {
      setAiMsg("Saving…");
      try {
        const body = { provider: prov.value, base_url: base.value.trim(),
          model: model.value.trim() };
        if (key.value) body.api_key = key.value;
        if (tmo && tmo.value) body.timeout = parseInt(tmo.value, 10);
        const r = await (await fetch("/api/ai/config", { method: "POST",
          headers: { "content-type": "application/json" }, body: JSON.stringify(body) })).json();
        key.value = "";
        setAiStatus(r.probe ? Object.assign({ config: r.config }, r.probe) : r);
        setAiMsg(r.probe && r.probe.ok ? "✓ connected" : ("· " + ((r.probe && r.probe.detail) || r.error || "saved")));
        if (lastResult) render(lastResult);   // re-render to show AI buttons
      } catch (e) { setAiMsg("❌ " + e); }
    };
  }
  function setAiStatus(s) {
    aiEnabled = !!(s && s.enabled && (s.ok || s.reachable));
    const el = $("#aiStatus"); if (!el) return;
    if (!s.enabled) { el.textContent = "off"; el.className = "aistatus"; }
    else if (s.ok) { el.textContent = (s.provider || "on") + " ✓"; el.className = "aistatus on"; }
    else { el.textContent = (s.provider || "on") + " ?"; el.className = "aistatus warn"; }
    document.body.classList.toggle("ai-on", aiEnabled);
  }
  function setAiMsg(t) { const m = $("#aiMsg"); if (m) m.textContent = t; }

  // minimal, safe markdown -> html (headers, code, bold, lists)
  function mdToHtml(md) {
    const lines = String(md).split("\n"); let html = "", inList = false, inCode = false;
    const inline = s => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    for (let ln of lines) {
      if (/^```/.test(ln)) { inCode = !inCode; html += inCode ? "<pre class='aicode'>" : "</pre>"; continue; }
      if (inCode) { html += esc(ln) + "\n"; continue; }
      let m;
      if ((m = ln.match(/^(#{1,4})\s+(.*)/))) { if (inList) { html += "</ul>"; inList = false; }
        const lvl = Math.min(m[1].length + 2, 5); html += `<h${lvl}>${inline(m[2])}</h${lvl}>`; continue; }
      if ((m = ln.match(/^\s*[-*]\s+(.*)/)) || (m = ln.match(/^\s*\d+\.\s+(.*)/))) {
        if (!inList) { html += "<ul>"; inList = true; } html += `<li>${inline(m[1])}</li>`; continue; }
      if (inList) { html += "</ul>"; inList = false; }
      if (ln.trim()) html += `<p>${inline(ln)}</p>`;
    }
    if (inList) html += "</ul>"; if (inCode) html += "</pre>";
    return html;
  }

  function findFinding(d, id) {
    const pools = [d.extra || [], d.findings || []];
    for (const p of pools) { const f = p.find(x => x.id === id); if (f) return f; }
    for (const b of ["root", "ssl"]) for (const m of (d[b] && d[b].mechanisms) || [])
      if (m.id === id) return m;
    // API endpoints use value as key
    for (const e of (d.api && d.api.endpoints) || []) if (e.id === id || e.value === id) return e;
    return null;
  }

  function wireAI(d) {
    // per-finding analyze buttons
    document.querySelectorAll(".ai-analyze").forEach(btn => btn.onclick = async () => {
      const out = btn.parentElement.querySelector(".ai-out");
      const f = findFinding(d, btn.dataset.fid);
      if (!f) { out.innerHTML = "<em>finding not found</em>"; return; }
      btn.disabled = true; out.innerHTML = "<span class='spinner'></span> asking your model…";
      try {
        const r = await (await fetch("/api/ai/finding", { method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ finding: f, meta: d.meta }) })).json();
        out.innerHTML = r.ok ? `<div class='aiout'>${mdToHtml(r.markdown)}</div>`
          : `<div class='aierr'>AI: ${esc(r.error || "unavailable")}${r.enabled === false ? " — configure a model above." : ""}</div>`;
      } catch (e) { out.innerHTML = `<div class='aierr'>${esc(String(e))}</div>`; }
      btn.disabled = false;
    });
    // pentest plan button
    const plan = $("#aiPlan");
    if (plan) plan.onclick = async () => {
      const host = $("#aiPlanOut");
      host.innerHTML = "<span class='spinner'></span> building an app-specific plan…";
      try {
        const r = await (await fetch("/api/ai/plan", { method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ result: d }) })).json();
        host.innerHTML = r.ok ? `<div class='aiout'>${mdToHtml(r.markdown)}</div>`
          : `<div class='aierr'>AI: ${esc(r.error || "unavailable")}${r.enabled === false ? " — configure a model above." : ""}</div>`;
      } catch (e) { host.innerHTML = `<div class='aierr'>${esc(String(e))}</div>`; }
    };
  }

  // ---- AI chatbot ----
  function initChat() {
    const fab = $("#chatFab"), panel = $("#chatPanel"), close = $("#chatClose"),
          body = $("#chatBody"), text = $("#chatText"), send = $("#chatSend");
    if (!fab) return;
    const history = [];   // {role, content}
    fab.onclick = () => { panel.classList.toggle("hidden"); if (!panel.classList.contains("hidden")) text.focus(); };
    if (close) close.onclick = () => panel.classList.add("hidden");
    function add(role, html, cls) {
      const d = document.createElement("div");
      d.className = "chatmsg " + (cls || role);
      d.innerHTML = html;
      body.appendChild(d); body.scrollTop = body.scrollHeight;
      return d;
    }
    async function submit() {
      const q = text.value.trim();
      if (!q) return;
      text.value = "";
      add("user", esc(q));
      history.push({ role: "user", content: q });
      const pending = add("bot", "<span class='spinner'></span> thinking…");
      try {
        const r = await (await fetch("/api/ai/chat", {
          method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ messages: history, result: lastResult }) })).json();
        if (r.ok) {
          pending.innerHTML = mdToHtml(r.reply);
          history.push({ role: "assistant", content: r.reply });
        } else {
          pending.className = "chatmsg err";
          pending.innerHTML = "AI: " + esc(r.error || "unavailable") + (r.enabled === false ? " — configure a model in the AI assist panel." : "");
        }
      } catch (e) { pending.className = "chatmsg err"; pending.textContent = String(e); }
    }
    if (send) send.onclick = submit;
    if (text) text.addEventListener("keydown", e => {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
    });
  }

  // small public API — render a previously saved result JSON
  window.ShieldScope = { render };
  initAI();
  initChat();
})();
