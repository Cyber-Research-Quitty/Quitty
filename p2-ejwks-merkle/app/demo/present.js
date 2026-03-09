const fmt = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

function text(id, value) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = value;
  }
}

function shortHash(value, size = 18) {
  if (!value) {
    return "-";
  }
  if (value.length <= size * 2) {
    return value;
  }
  return `${value.slice(0, size)}...${value.slice(-size)}`;
}

function bloomMetric(metrics, name) {
  return metrics?.[name] ?? 0;
}

function pct(value) {
  return `${((value ?? 0) * 100).toFixed(1)}%`;
}

async function loadPresentationData() {
  const response = await fetch("/dashboard/data", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`presentation data request failed: ${response.status}`);
  }
  return response.json();
}

function renderPresentation(data) {
  const counts = data.counts || {};
  const active = counts.active ?? 0;
  const inactive = counts.inactive ?? 0;
  const total = counts.total ?? 0;
  const jwksRoot = data.jwks_root || {};
  const logRoot = data.log_root || {};
  const latestCheckpoint = data.latest_checkpoint || {};
  const keyTree = data.merkle_tree || {};
  const logTree = data.log_merkle_tree || {};
  const bloom = data.bloom_filter || {};
  const bloomMetrics = bloom.metrics || {};
  const kidSummary = bloom.kid_request_summary || {};
  const refreshedAt = data.generated_at ? fmt.format(new Date(data.generated_at * 1000)) : "Unknown";

  text("hero-active", String(active));
  text("hero-root", jwksRoot.root_hash || "No JWKS root available");
  text(
    "hero-meta",
    `Checkpoint ${latestCheckpoint.idx ?? "-"} | Refreshed ${refreshedAt}`
  );

  text("component-keys", `${total} total keys, ${active} active, ${inactive} inactive`);
  text(
    "component-tree",
    `${keyTree.leaf_count ?? 0} leaves across ${keyTree.level_count ?? 0} levels`
  );
  text(
    "component-log-tree",
    `${logTree.leaf_count ?? 0} checkpoints across ${logTree.level_count ?? 0} levels`
  );
  text("component-proof", "/jwks/proof/{kid} and /log/checkpoint/{idx}");
  text(
    "component-bloom",
    bloom.enabled
      ? `${bloom.m_bits ?? 0} bits, ${bloom.k_hashes ?? 0} hashes, ${bloom.indexed_items ?? 0} indexed values`
      : "Bloom filter disabled"
  );

  text("bloom-miss-hint", bloom.miss_semantics || "If Bloom says no, the key is definitely not present.");
  text("bloom-hit-hint", bloom.hit_semantics || "If Bloom says maybe, continue to full lookup.");
  text("bloom-indexed-items", `${bloom.indexed_items ?? 0} total values`);
  text("bloom-kid-queries", String(bloomMetric(bloomMetrics, "kid_queries_total")));
  text("bloom-definite-misses", String(bloomMetric(bloomMetrics, "kid_definite_miss_total")));
  text("bloom-maybe-present", String(bloomMetric(bloomMetrics, "kid_maybe_present_total")));
  text("bloom-allowed-requests", String(kidSummary.allowed_total ?? 0));
  text("bloom-rejected-requests", String(kidSummary.rejected_total ?? 0));
  text("bloom-request-rates", `${pct(kidSummary.allow_rate)} / ${pct(kidSummary.reject_rate)}`);

  text("evidence-status", `${active} active / ${inactive} inactive`);
  text(
    "evidence-checkpoint",
    latestCheckpoint.idx != null
      ? `#${latestCheckpoint.idx} at epoch ${latestCheckpoint.epoch ?? "-"}`
      : "No checkpoint available"
  );
  text("evidence-log-root", shortHash(logRoot.root_hash || "No log root available", 20));
}

function renderError(error) {
  const message = `Unable to load live P2 data: ${error.message}`;
  text("hero-root", message);
  text("hero-meta", "Check /dashboard/data and the P2 service state.");
  text("component-keys", message);
  text("component-tree", message);
  text("component-log-tree", message);
  text("component-proof", message);
  text("component-bloom", message);
  text("bloom-miss-hint", message);
  text("bloom-hit-hint", message);
  text("bloom-indexed-items", message);
  text("bloom-kid-queries", message);
  text("bloom-definite-misses", message);
  text("bloom-maybe-present", message);
  text("bloom-allowed-requests", message);
  text("bloom-rejected-requests", message);
  text("bloom-request-rates", message);
  text("evidence-status", message);
  text("evidence-checkpoint", message);
  text("evidence-log-root", message);
}

async function refresh() {
  try {
    const data = await loadPresentationData();
    renderPresentation(data);
  } catch (error) {
    renderError(error);
  }
}

refresh();
window.setInterval(refresh, 5000);
