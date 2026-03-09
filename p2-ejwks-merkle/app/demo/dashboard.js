const refreshMs = 5000;
let selectedKeyKid = null;
let selectedCheckpointIdx = null;
let lastSnapshot = null;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function fmtDate(epoch) {
  if (!epoch) return "-";
  return new Date(epoch * 1000).toLocaleString();
}

function shortHash(value, size = 18) {
  if (!value) return "-";
  if (value.length <= size) return value;
  return value.slice(0, size) + "...";
}

function setText(id, value) {
  document.getElementById(id).textContent = value ?? "-";
}

function setHtml(id, html) {
  document.getElementById(id).innerHTML = html;
}

function bloomMetric(metrics, name) {
  return metrics?.[name] ?? 0;
}

function pct(value) {
  return `${((value ?? 0) * 100).toFixed(1)}%`;
}

function percentWidth(value, total) {
  if (!total) return "0%";
  return `${(Math.max(value, 0) / total) * 100}%`;
}

function renderBloomLegendItem(label, value, rate, swatchClass) {
  return `
    <div class="bloom-legend-item">
      <span class="bloom-swatch ${swatchClass}"></span>
      <span class="bloom-legend-label">${escapeHtml(label)}</span>
      <span class="bloom-legend-value">${escapeHtml(String(value))} · ${escapeHtml(pct(rate))}</span>
    </div>
  `;
}

function renderBloomPanel(bloom) {
  const metrics = bloom.metrics || {};
  const kidSummary = bloom.kid_request_summary || {};
  const totalQueries = kidSummary.total_queries ?? 0;
  const allowedTotal = kidSummary.allowed_total ?? 0;
  const rejectedTotal = kidSummary.rejected_total ?? 0;
  const maybePresent = bloomMetric(metrics, "kid_maybe_present_total");
  const definiteMisses = bloomMetric(metrics, "kid_definite_miss_total");
  const cacheHits = kidSummary.allowed_breakdown?.cache_hits ?? 0;
  const rebuildHits = kidSummary.allowed_breakdown?.hits_after_rebuild ?? 0;

  const decisionTotal = maybePresent + definiteMisses;
  const allowBreakdownTotal = cacheHits + rebuildHits;

  setHtml("bloom-panel-body", `
    <div class="bloom-panel">
      <div class="bloom-kpis">
        <div class="bloom-kpi">
          <div class="bloom-kpi-label">Configuration</div>
          <div class="bloom-kpi-value">${bloom.enabled ? `${escapeHtml(String(bloom.m_bits ?? 0))} bits / ${escapeHtml(String(bloom.k_hashes ?? 0))} hashes` : "Disabled"}</div>
        </div>
        <div class="bloom-kpi">
          <div class="bloom-kpi-label">Indexed Items</div>
          <div class="bloom-kpi-value">${escapeHtml(String(bloom.indexed_items ?? 0))} items (${escapeHtml(String(bloom.indexed_kids ?? 0))} kid + ${escapeHtml(String(bloom.indexed_jkts ?? 0))} JKT)</div>
        </div>
      </div>

      <div class="bloom-charts">
        <section class="bloom-chart">
          <div class="bloom-chart-head">
            <div class="bloom-chart-title">Request Outcomes</div>
            <div class="bloom-chart-summary">${escapeHtml(String(totalQueries))} total key lookups</div>
          </div>
          <div class="bloom-bar-track">
            <div class="bloom-bar-segment bloom-bar-allowed" style="width: ${percentWidth(allowedTotal, totalQueries)}"></div>
            <div class="bloom-bar-segment bloom-bar-rejected" style="width: ${percentWidth(rejectedTotal, totalQueries)}"></div>
          </div>
          <div class="bloom-legend">
            ${renderBloomLegendItem("Allowed", allowedTotal, kidSummary.allow_rate ?? 0, "bloom-bar-allowed")}
            ${renderBloomLegendItem("Rejected", rejectedTotal, kidSummary.reject_rate ?? 0, "bloom-bar-rejected")}
          </div>
        </section>

        <section class="bloom-chart">
          <div class="bloom-chart-head">
            <div class="bloom-chart-title">Bloom Decisions</div>
            <div class="bloom-chart-summary">pre-check result before proof lookup</div>
          </div>
          <div class="bloom-bar-track">
            <div class="bloom-bar-segment bloom-bar-maybe" style="width: ${percentWidth(maybePresent, decisionTotal)}"></div>
            <div class="bloom-bar-segment bloom-bar-definite" style="width: ${percentWidth(definiteMisses, decisionTotal)}"></div>
          </div>
          <div class="bloom-legend">
            ${renderBloomLegendItem("Maybe present", maybePresent, decisionTotal ? maybePresent / decisionTotal : 0, "bloom-bar-maybe")}
            ${renderBloomLegendItem("Definitely not present", definiteMisses, decisionTotal ? definiteMisses / decisionTotal : 0, "bloom-bar-definite")}
          </div>
        </section>

        <section class="bloom-chart">
          <div class="bloom-chart-head">
            <div class="bloom-chart-title">Allowed Path Breakdown</div>
            <div class="bloom-chart-summary">how successful lookups resolved</div>
          </div>
          <div class="bloom-bar-track">
            <div class="bloom-bar-segment bloom-bar-cache" style="width: ${percentWidth(cacheHits, allowBreakdownTotal)}"></div>
            <div class="bloom-bar-segment bloom-bar-rebuild" style="width: ${percentWidth(rebuildHits, allowBreakdownTotal)}"></div>
          </div>
          <div class="bloom-legend">
            ${renderBloomLegendItem("Cache hit", cacheHits, allowBreakdownTotal ? cacheHits / allowBreakdownTotal : 0, "bloom-bar-cache")}
            ${renderBloomLegendItem("Hit after rebuild", rebuildHits, allowBreakdownTotal ? rebuildHits / allowBreakdownTotal : 0, "bloom-bar-rebuild")}
          </div>
        </section>
      </div>

      <div class="bloom-hints">
        <div class="bloom-hint negative">
          <div class="detail-label">Definitely Not Present</div>
          <div class="detail-value">${escapeHtml(bloom.miss_semantics || "-")}</div>
        </div>
        <div class="bloom-hint positive">
          <div class="detail-label">Maybe Present</div>
          <div class="detail-value">${escapeHtml(bloom.hit_semantics || "-")}</div>
        </div>
      </div>
    </div>
  `);
}

function renderKeys(keys) {
  const body = document.getElementById("keys-body");
  if (!keys.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No keys found.</td></tr>';
    return;
  }

  body.innerHTML = keys.map((key) => `
    <tr>
      <td><code>${escapeHtml(key.kid)}</code></td>
      <td><span class="badge ${escapeHtml(key.status)}">${escapeHtml(key.status)}</span></td>
      <td>${escapeHtml(key.kty || "-")}</td>
      <td>${escapeHtml(key.alg || "-")}</td>
      <td>${escapeHtml(fmtDate(key.activated_at))}</td>
      <td>${escapeHtml(fmtDate(key.deactivated_at))}</td>
      <td><code>${escapeHtml(shortHash(key.jkt, 22))}</code></td>
    </tr>
  `).join("");
}

function renderCheckpoints(checkpoints) {
  const body = document.getElementById("checkpoints-body");
  if (!checkpoints.length) {
    body.innerHTML = '<tr><td colspan="4" class="empty">No checkpoints found.</td></tr>';
    return;
  }

  body.innerHTML = checkpoints.map((checkpoint) => `
    <tr>
      <td>${escapeHtml(checkpoint.idx)}</td>
      <td>${escapeHtml(checkpoint.epoch)}</td>
      <td>${escapeHtml(fmtDate(checkpoint.created_at))}</td>
      <td><code>${escapeHtml(shortHash(checkpoint.jwks_root_hash, 28))}</code></td>
    </tr>
  `).join("");
}

function proofStepsHtml(steps) {
  if (!Array.isArray(steps) || !steps.length) {
    return '<div class="empty">No proof path items were returned.</div>';
  }

  return `
    <div class="proof-steps">
      ${steps.map((step, index) => `
        <div class="proof-step">
          <div class="proof-step-title">Step ${index + 1} | sibling on ${escapeHtml(step.position || "-")}</div>
          <div class="proof-step-value">${escapeHtml(step.hash || "-")}</div>
        </div>
      `).join("")}
    </div>
  `;
}

function applySelectedNodes() {
  document.querySelectorAll(".tree-node.clickable").forEach((node) => {
    const treeType = node.dataset.treeType;
    const isSelected =
      (treeType === "key" && selectedKeyKid && node.dataset.leafId === selectedKeyKid) ||
      (treeType === "log" && selectedCheckpointIdx && node.dataset.checkpointIdx === String(selectedCheckpointIdx));
    node.classList.toggle("selected", Boolean(isSelected));
  });
}

function clearKeyProof(message = "Click a key leaf in the key Merkle tree to load its inclusion proof.") {
  setText("key-proof-summary", "No key selected");
  setHtml("key-proof-body", `<div class="empty">${escapeHtml(message)}</div>`);
}

function clearLogProof(message = "Click a checkpoint leaf in the transparency log tree to load its inclusion proof.") {
  setText("log-proof-summary", "No checkpoint selected");
  setHtml("log-proof-body", `<div class="empty">${escapeHtml(message)}</div>`);
}

async function loadKeyProof(kid) {
  try {
    setText("key-proof-summary", `Loading ${kid}...`);
    const response = await fetch(`/jwks/proof/${encodeURIComponent(kid)}`, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`proof request failed: ${response.status}`);
    }
    const data = await response.json();
    setText("key-proof-summary", `Selected key: ${kid}`);
    setHtml("key-proof-body", `
      <div class="detail-list">
        <div class="detail">
          <div class="detail-label">JKT</div>
          <div class="detail-value">${escapeHtml(data.jkt || "-")}</div>
        </div>
        <div class="detail">
          <div class="detail-label">Signed Root Hash</div>
          <div class="detail-value">${escapeHtml(data.root?.root_hash || "-")}</div>
        </div>
        <div class="detail">
          <div class="detail-label">Latest Checkpoint Idx</div>
          <div class="detail-value">${escapeHtml(data.latest_checkpoint_idx ?? "-")}</div>
        </div>
      </div>
      ${proofStepsHtml(data.merkle_proof)}
    `);
  } catch (error) {
    setText("key-proof-summary", `Selected key: ${kid}`);
    setHtml("key-proof-body", `<div class="empty">Failed to load key proof: ${escapeHtml(error.message)}</div>`);
  }
  applySelectedNodes();
}

async function loadLogProof(checkpointIdx) {
  try {
    setText("log-proof-summary", `Loading checkpoint #${checkpointIdx}...`);
    const response = await fetch(`/log/checkpoint/${encodeURIComponent(checkpointIdx)}`, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`log proof request failed: ${response.status}`);
    }
    const data = await response.json();
    setText("log-proof-summary", `Selected checkpoint: #${checkpointIdx}`);
    setHtml("log-proof-body", `
      <div class="detail-list">
        <div class="detail">
          <div class="detail-label">Checkpoint Entry Hash</div>
          <div class="detail-value">${escapeHtml(data.checkpoint?.entry_hash || "-")}</div>
        </div>
        <div class="detail">
          <div class="detail-label">Checkpoint JWKS Root Hash</div>
          <div class="detail-value">${escapeHtml(data.checkpoint?.jwks_root_hash || "-")}</div>
        </div>
        <div class="detail">
          <div class="detail-label">Log Root Hash</div>
          <div class="detail-value">${escapeHtml(data.log_root?.root_hash || "-")}</div>
        </div>
      </div>
      ${proofStepsHtml(data.inclusion_proof)}
    `);
  } catch (error) {
    setText("log-proof-summary", `Selected checkpoint: #${checkpointIdx}`);
    setHtml("log-proof-body", `<div class="empty">Failed to load checkpoint proof: ${escapeHtml(error.message)}</div>`);
  }
  applySelectedNodes();
}

function renderTree(tree, hostId, summaryId, treeType) {
  const host = document.getElementById(hostId);
  const summary = document.getElementById(summaryId);

  if (!tree || !Array.isArray(tree.levels) || !tree.levels.length) {
    host.innerHTML = '<div class="empty">Merkle tree data is not available.</div>';
    summary.textContent = "No tree data";
    return;
  }

  summary.textContent = `${tree.leaf_count ?? 0} leaves / ${tree.level_count ?? 0} levels`;
  const gridColumns = Math.max(tree.leaf_count || 1, 1);

  const levelHtml = tree.levels.map((level) => `
    <div class="tree-row" style="grid-template-columns: repeat(${gridColumns}, minmax(120px, 1fr));">
      ${level.nodes.map((node) => {
        const start = (node.span_start ?? node.index ?? 0) + 1;
        const endExclusive = (node.span_end ?? node.span_start ?? node.index ?? 0) + 2;
        const nodeTitle = node.kind === "leaf"
          ? escapeHtml(node.leaf_label || node.leaf_id || `Leaf ${node.index}`)
          : escapeHtml(level.label);
        const nodeMeta = node.kind === "leaf"
          ? (node.leaf_meta || `Leaf #${(node.index ?? 0) + 1}`)
          : (node.span_start != null && node.span_end != null
              ? `Leaves ${node.span_start + 1}-${node.span_end + 1}`
              : "Empty tree");
        const isClickable = node.kind === "leaf";
        const extraAttrs = isClickable
          ? (treeType === "key"
              ? `data-tree-type="key" data-leaf-id="${escapeHtml(node.leaf_id || "")}"`
              : `data-tree-type="log" data-checkpoint-idx="${escapeHtml(node.checkpoint_idx || "")}"`)
          : "";
        return `
          <article class="tree-node ${escapeHtml(node.kind)} ${isClickable ? "clickable" : ""}" ${extraAttrs} style="grid-column: ${start} / ${endExclusive};">
            <div class="tree-node-label">${escapeHtml(node.kind)}</div>
            <div class="tree-node-title">${nodeTitle}</div>
            <div class="tree-node-hash">${escapeHtml(shortHash(node.hash, 28))}</div>
            <div class="tree-node-meta">${escapeHtml(nodeMeta)}</div>
          </article>
        `;
      }).join("")}
    </div>
  `).join("");

  const leafStrip = Array.isArray(tree.leaves) && tree.leaves.length
    ? `
      <div class="leaf-strip">
        ${tree.leaves.map((leaf, index) => `
          <div class="leaf-pill">
            <span class="leaf-pill-index">${index + 1}</span>
            <code>${escapeHtml(leaf.leaf_label || leaf.leaf_id || `Leaf ${index + 1}`)}</code>
          </div>
        `).join("")}
      </div>
    `
    : "";

  host.innerHTML = `
    <div class="tree-canvas">
      ${levelHtml}
    </div>
    ${leafStrip}
  `;
  applySelectedNodes();
}

function syncSelectionWithSnapshot() {
  const keyLeaves = new Set((lastSnapshot?.merkle_tree?.leaves || []).map((leaf) => leaf.leaf_id));
  if (selectedKeyKid && !keyLeaves.has(selectedKeyKid)) {
    selectedKeyKid = null;
    clearKeyProof("The previously selected key is no longer present in the live key tree.");
  }

  const checkpointLeaves = new Set((lastSnapshot?.log_merkle_tree?.leaves || []).map((leaf) => String(leaf.checkpoint_idx)));
  if (selectedCheckpointIdx && !checkpointLeaves.has(String(selectedCheckpointIdx))) {
    selectedCheckpointIdx = null;
    clearLogProof("The previously selected checkpoint is no longer present in the live transparency log tree.");
  }
}

function initTreeInteractions() {
  document.addEventListener("click", async (event) => {
    const node = event.target.closest(".tree-node.clickable");
    if (!node) {
      return;
    }

    if (node.dataset.treeType === "key" && node.dataset.leafId) {
      selectedKeyKid = node.dataset.leafId;
      await loadKeyProof(selectedKeyKid);
      return;
    }

    if (node.dataset.treeType === "log" && node.dataset.checkpointIdx) {
      selectedCheckpointIdx = node.dataset.checkpointIdx;
      await loadLogProof(selectedCheckpointIdx);
    }
  });
}

async function refreshDashboard() {
  const response = await fetch("/dashboard/data", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`dashboard data request failed: ${response.status}`);
  }

  const data = await response.json();
  lastSnapshot = data;
  const counts = data.counts || {};
  const jwksRoot = data.jwks_root || {};
  const logRoot = data.log_root || {};
  const latestCheckpoint = data.latest_checkpoint || {};
  const bloom = data.bloom_filter || {};
  const bloomMetrics = bloom.metrics || {};
  const kidSummary = bloom.kid_request_summary || {};
  const keys = (data.keys || []).slice().sort((a, b) => {
    if (a.status === b.status) return a.kid.localeCompare(b.kid);
    return a.status === "active" ? -1 : 1;
  });

  setText("stat-total", counts.total ?? 0);
  setText("stat-active", counts.active ?? 0);
  setText("stat-inactive", counts.inactive ?? 0);
  setText("stat-checkpoint", latestCheckpoint.idx ?? "-");
  setText("stat-epoch", jwksRoot.epoch ?? latestCheckpoint.epoch ?? "-");

  setText("hero-root", jwksRoot.root_hash || latestCheckpoint.jwks_root_hash || "No root available");
  setText(
    "hero-root-meta",
    jwksRoot.epoch
      ? `Epoch ${jwksRoot.epoch} | ${fmtDate(jwksRoot.epoch)}`
      : "No signed JWKS root is cached"
  );

  setText("detail-jwks-root", jwksRoot.root_hash || latestCheckpoint.jwks_root_hash || "-");
  setText("detail-jwks-signer", jwksRoot.sig_kid || "-");
  setText("detail-log-root", logRoot.root_hash || "-");
  setText("detail-checkpoint-entry", latestCheckpoint.entry_hash || "-");
  renderBloomPanel(bloom);
  setText("key-summary", `${counts.active ?? 0} active / ${counts.inactive ?? 0} inactive`);
  setText("last-refresh", `Last refresh: ${fmtDate(data.generated_at)}`);

  syncSelectionWithSnapshot();
  renderKeys(keys);
  renderCheckpoints(data.recent_checkpoints || []);
  renderTree(data.merkle_tree || {}, "merkle-tree", "tree-summary", "key");
  renderTree(data.log_merkle_tree || {}, "log-merkle-tree", "log-tree-summary", "log");
  applySelectedNodes();
}

async function tick() {
  try {
    await refreshDashboard();
  } catch (error) {
    setText("last-refresh", `Refresh failed: ${error.message}`);
  }
}

initTreeInteractions();
clearKeyProof();
clearLogProof();
tick();
setInterval(tick, refreshMs);
