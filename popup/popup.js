const API_BASE = "https://threatlens-api.vercel.app";

const urlDisplay = document.getElementById("url-display");
const fullUrlToggle = document.getElementById("full-url-toggle");
const scanModeLabel = document.getElementById("scan-mode-label");
const scoreEl = document.getElementById("score-value");
const ringProgress = document.getElementById("score-ring");
const riskText = document.getElementById("risk-text");
const riskIcon = document.getElementById("verdict-dot");
const riskDescription = document.getElementById("risk-description");
const recentScanLabel = document.getElementById("recent-scan-label");
const domainAgeCard = document.getElementById("domain-age");
const domainAgeDisplay = document.getElementById("domain-age-text");
const threatExpl = document.getElementById("ai-summary-section");
const explanationText = document.getElementById("threat-analysis-text");
const aiSummaryBtn = document.getElementById("ai-summary-btn");
const aiSummaryPanel = document.getElementById("ai-summary-panel");
const scanBtn = document.getElementById("scan-btn");
const resultArea = document.getElementById("result-area");
const checklistEl = document.getElementById("checklist");
const threatIndicators = document.getElementById("threat-indicators");
const sellerInsightsSection = document.getElementById("seller-insights-section");
const sellerInsightsBtn = document.getElementById("seller-insights-btn");
const sellerInsightsPanel = document.getElementById("seller-insights-panel");
const sellerInsightsList = document.getElementById("seller-insights-list");
const sellerFavicon = document.getElementById("seller-favicon");
const headerMenuBtn = document.getElementById("header-menu-btn");
const headerMenuPanel = document.getElementById("header-menu-panel");
const supportMenuBtn = document.getElementById("support-menu-btn");
const supportSubmenu = document.getElementById("support-submenu");
const themeToggle = document.getElementById("theme-toggle");

// Updated selector for the new HTML structure: <span class="btn-label">
const scanBtnTextEl = scanBtn ? scanBtn.querySelector(".btn-label") : null;

let copiedButtonTimer = null;
const THEME_STORAGE_KEY = "threatlens-theme";
const SCAN_CACHE_STORAGE_KEY = "threatlens-scan-cache-seller-evidence-v9";
const SCAN_CACHE_TTL_MS = 5 * 60 * 1000;
const DETAIL_CACHE_TTL_MS = 10 * 60 * 1000;

const C = {
  safe: { color: "var(--color-success)", shadow: "var(--shadow-success)" },
  medium: { color: "var(--color-warning)", shadow: "var(--shadow-warning)" },
  high: { color: "var(--color-danger)", shadow: "var(--shadow-danger)" },
};

const state = {
  currentTabUrl: "",
  currentTabId: null,
  scanRevision: 0,
  lastScannedUrl: "",
  activeScanUrl: "",
  lastAnalysis: null,
  sellerInsightsLoadedFor: "",
  aiSummary: null,
  aiSummaryRequest: null,
};

const ICONS = {
  phone: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.8 19.8 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.08 4.18 2 2 0 0 1 4.06 2h3a2 2 0 0 1 2 1.72c.12.9.33 1.77.62 2.62a2 2 0 0 1-.45 2.11L8 9.91a16 16 0 0 0 6.09 6.09l1.46-1.23a2 2 0 0 1 2.11-.45c.85.29 1.72.5 2.62.62A2 2 0 0 1 22 16.92z"></path></svg>`,
  whatsapp: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 21.01h-.01c-1.6 0-3.17-.43-4.54-1.24l-.33-.19-3.37.89.9-3.28-.21-.34c-.84-1.34-1.29-2.9-1.29-4.51C2.15 7.11 6.57 2.68 12 2.68c2.62 0 5.09 1.02 6.94 2.88a9.8 9.8 0 0 1 2.87 6.96c-.01 5.44-4.42 9.49-9.81 9.49z"/><path stroke-width="1.6" d="M17.47 14.39c-.3-.15-1.76-.87-2.03-.97-.27-.1-.47-.15-.67.15-.2.3-.77.97-.94 1.17-.17.2-.35.22-.64.07a9.1 9.1 0 0 1-2.39-1.48 9.1 9.1 0 0 1-1.65-2.06c-.17-.3 0-.46.15-.6.13-.14.3-.35.45-.52.15-.18.2-.3.3-.5.1-.2.05-.37-.03-.52-.07-.15-.67-1.61-.91-2.2-.25-.6-.49-.5-.67-.51-.17 0-.37-.01-.57-.01-.2 0-.52.07-.79.37s-1.04 1-1.04 2.48 1.07 2.88 1.21 3.07 2.1 3.2 5.08 4.49c.7.3 1.26.49 1.69.63.71.23 1.36.2 1.87.12.57-.09 1.76-.72 2.01-1.41.25-.7.25-1.29.17-1.41-.08-.13-.27-.2-.57-.35z"/></svg>`,
  email: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16v16H4z"></path><path d="m4 7 8 6 8-6"></path></svg>`,
  policy: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 3h7v7"></path><path d="M10 14 21 3"></path><path d="M21 14v7H3V3h7"></path></svg>`,
  whois: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M2 12h20"></path><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>`,
  copy: `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`,
  check: `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
  warning: `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.29 3.86 1.82 18A2 2 0 0 0 3.53 21h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path></svg>`,
};

function pal(t) {
  return t <= 0.3 ? C.safe : t <= 0.5 ? C.medium : C.high;
}

function ageColour(days) {
  if (days == null || days < 0) return "var(--color-text-muted)";
  if (days >= 365) return "var(--color-success)";
  if (days >= 90) return "var(--color-warning)";
  return "var(--color-danger)";
}

function indicatorTone(type) {
  if (type === "check") return "safe";
  if (type === "warn") return "warning";
  if (type === "cross") return "danger";
  return "unknown";
}

function indicatorRow(type, colour, label, statusText) {
  const tone = indicatorTone(type);
  const paths = {
    check: `<polyline points="20 6 9 17 4 12"/>`,
    warn: `<path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>`,
    cross: `<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>`,
  };
  const statusHtml = statusText
    ? `<span class="indicator-status tone-${tone}">${statusText}</span>`
    : "";
  return `<div class="indicator" role="listitem">
    <svg class="indicator-icon tone-${tone}" width="13" height="13" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"
      aria-hidden="true">${paths[type]}</svg>
    <span class="indicator-label">${label}</span>
    ${statusHtml}
  </div>`;
}

function normaliseUrl(raw) {
  const trimmed = (raw || "").trim();
  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed) && !/^https?:\/\//i.test(trimmed) && !/^[^/:]+:\d+(?:[/?#]|$)/.test(trimmed)) return "";
  if (!trimmed) return "";
  if (/^https?:\/\//i.test(trimmed)) {
    try { return new URL(trimmed).toString(); } catch { return ""; }
  }
  try { return new URL(`https://${trimmed}`).toString(); } catch { return ""; }
}

function urlForScan(rawUrl) {
  const normalised = normaliseUrl(rawUrl);
  if (!normalised) return "";
  if (fullUrlToggle.checked) return normalised;
  try { return new URL(normalised).origin; } catch { return normalised; }
}

function presentUrl(rawUrl) {
  const normalised = normaliseUrl(rawUrl);
  if (!normalised) return rawUrl || "";
  return fullUrlToggle.checked ? normalised : new URL(normalised).host;
}

function matchesKnownDisplayVariant(rawInput, knownUrl) {
  const typed = (rawInput || "").trim();
  const normalised = normaliseUrl(knownUrl);
  if (!typed || !normalised) return false;
  try {
    const parsed = new URL(normalised);
    return typed === normalised || typed === parsed.host || typed === parsed.origin;
  } catch {
    return typed === normalised;
  }
}

function resolveDisplaySource(rawInput) {
  if (matchesKnownDisplayVariant(rawInput, state.currentTabUrl)) return state.currentTabUrl;
  if (matchesKnownDisplayVariant(rawInput, state.lastScannedUrl)) return state.lastScannedUrl;
  return rawInput;
}

function updateScanModeLabel() {
  if (!scanModeLabel) return;
  scanModeLabel.textContent = fullUrlToggle.checked ? "Scanning: Full URL" : "Domain only";
}

function applyTheme(theme) {
  document.body.dataset.theme = theme === "dark" ? "dark" : "light";
  if (themeToggle) {
    themeToggle.setAttribute("aria-label",
      theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
    themeToggle.setAttribute("title",
      theme === "dark" ? "Light mode" : "Dark mode");
  }
}

function loadThemePreference() {
  const stored = localStorage.getItem(THEME_STORAGE_KEY);
  applyTheme(stored === "dark" ? "dark" : "light");
}

function toggleTheme() {
  const next = document.body.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(next);
  localStorage.setItem(THEME_STORAGE_KEY, next);
}

/* ── Cache helpers ── */
function readScanCache() {
  try {
    const raw = localStorage.getItem(SCAN_CACHE_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch { return {}; }
}

function writeScanCache(cache) {
  try { localStorage.setItem(SCAN_CACHE_STORAGE_KEY, JSON.stringify(cache)); } catch { }
}

function buildCacheKey(path, payload) {
  return `${path}::${payload?.url || ""}${path === "/explain" ? `::${JSON.stringify(payload)}` : payload?.signals ? `::${JSON.stringify(payload.signals)}` : ""}`;
}

function pruneExpiredCacheEntries(cache) {
  const now = Date.now();
  const next = {};
  Object.entries(cache || {}).forEach(([key, entry]) => {
    if (entry && typeof entry.expiresAt === "number" && entry.expiresAt > now) next[key] = entry;
  });
  return next;
}

function getCachedResponse(path, payload) {
  const cache = pruneExpiredCacheEntries(readScanCache());
  const key = buildCacheKey(path, payload);
  const entry = cache[key];
  writeScanCache(cache);
  return entry || null;
}

function setCachedResponse(path, payload, data, ttlMs) {
  const cache = pruneExpiredCacheEntries(readScanCache());
  const key = buildCacheKey(path, payload);
  cache[key] = { data, savedAt: Date.now(), expiresAt: Date.now() + ttlMs };
  // Evidence can be larger than the old boolean signals. Keep storage bounded.
  const oldest = Object.keys(cache).sort((a, b) => cache[a].savedAt - cache[b].savedAt);
  while (oldest.length > 8) delete cache[oldest.shift()];
  writeScanCache(cache);
}

function formatRelativeCacheAge(savedAt) {
  if (!savedAt) return "Recent scan";
  const minutes = Math.floor(Math.max(0, Date.now() - savedAt) / 60000);
  if (minutes <= 0) return "Just scanned";
  if (minutes === 1) return "Scanned 1 min ago";
  return `Scanned ${minutes} mins ago`;
}

function showRecentScanLabel(savedAt) {
  if (!recentScanLabel) return;
  recentScanLabel.textContent = formatRelativeCacheAge(savedAt);
  recentScanLabel.classList.remove("hidden");
}

function hideRecentScanLabel() {
  if (!recentScanLabel) return;
  recentScanLabel.textContent = "";
  recentScanLabel.classList.add("hidden");
}

/* ── Formatting helpers ── */
function formatSellerPhone(phone) {
  const raw = (phone || "").trim();
  if (!raw || raw === "Not found") return raw || "Not found";
  const compact = raw.replace(/\s+/g, "");
  if (/^\+91\d{10}$/.test(compact)) return `+91 ${compact.slice(3)}`;
  return raw.replace(/^\+91(?=\d{10}$)/, "+91 ");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function highlightPolicySummary(text) {
  const amount = String.raw`\d+(?:,\d+)*(?:\.\d+)?`;
  const range = String.raw`${amount}(?:\s*(?:[-–—]|\bto\b)\s*${amount})?`;
  const pattern = new RegExp(String.raw`(?:[₹$€£]|\b(?:Rs\.?|INR|USD|EUR|GBP)\s*)\s*${range}|\b${range}\s*(?:(?:(?:bank|business|working|calendar)\s+)*(?:hours?|days?|weeks?|months?|minutes?)|rupees?|INR|USD|EUR|GBP)\b|\b${range}\s*%`, "gi");
  let output = "";
  let offset = 0;
  for (const match of text.matchAll(pattern)) {
    output += escapeHtml(text.slice(offset, match.index));
    output += `<span class="policy-emphasis">${escapeHtml(match[0])}</span>`;
    offset = match.index + match[0].length;
  }
  return output + escapeHtml(text.slice(offset));
}

function summaryLines(summary) {
  if (Array.isArray(summary)) return summary.filter(point => typeof point === "string");
  const rows = summary.split(/\r?\n|[●•▪◦]/);
  // Older responses supplied a single paragraph, sometimes with inline bullets.
  return rows.length > 1 ? rows : summary.split(/(?<!\bRs\.)(?<!\bNo\.)(?<=[.!?])\s+/i);
}

function renderSummaryPoints(summary, policy = false) {
  const points = [...new Set(summaryLines(summary).map(point => point.trim().replace(/^(?:[-*–—]\s+|\d+[.)]\s+)/, ""))
    .filter(point => point && point.length <= 450))];
  if (!points.length) return "";
  const format = policy ? highlightPolicySummary : escapeHtml;
  return `<ul class="summary-points">${points.slice(0, policy ? 4 : 3).map(point => `<li>${format(point)}</li>`).join("")}</ul>`;
}

function formatPhoneWithFallback(value, fallbackValue) {
  const primary = formatSellerPhone(value || "");
  if (primary && primary !== "Not found") return primary;
  return formatSellerPhone(fallbackValue || "") || "Not found";
}

function buildWhatsappMeta(number) {
  const clean = (number || "").trim();
  if (!clean || clean === "Not found") return "";
  return `<div class="seller-inline-meta">
    <span class="seller-inline-chip whatsapp-chip">
      ${ICONS.whatsapp}<span>${escapeHtml(clean)}</span>
      <button class="icon-button inline-copy" type="button"
        data-kind="copy" data-payload="${escapeHtml(clean)}" title="Copy WhatsApp number">
        ${ICONS.copy}
      </button>
    </span>
  </div>`;
}

/* ── Ring & Verdict ── */
function animateRing(threat) {
  const safety = Math.round((1 - threat) * 100);
  const col = pal(threat);
  scoreEl.textContent = safety;
  scoreEl.style.color = col.color;
  const r = +ringProgress.getAttribute("r") || 42;
  const circ = 2 * Math.PI * r;
  ringProgress.style.strokeDasharray = circ;
  ringProgress.style.strokeDashoffset = circ * threat;
  ringProgress.style.stroke = col.color;
}

function setVerdict(verdict, threat) {
  const limited = verdict === "Limited Evidence";
  const col = limited ? pal(0.4) : pal(threat);
  const label = verdict || (threat <= 0.3 ? "Safe" : threat <= 0.5 ? "Medium Risk" : "High Risk");
  riskText.textContent = label.toUpperCase();
  riskText.style.color = col.color;
  riskText.classList.remove("is-scanning");
  riskIcon.style.background = col.color;
  riskIcon.style.boxShadow = `0 0 6px ${col.shadow}`;
  riskDescription.textContent = limited ? "Requested page content could not be read." : "";
}

function renderDomainAge(days) {
  domainAgeDisplay.style.color = ageColour(days);
  if (days == null || days < 0) {
    domainAgeDisplay.textContent = "Unknown";
  } else if (days < 30) {
    domainAgeDisplay.textContent = `${days} days old`;
  } else if (days < 365) {
    domainAgeDisplay.textContent = `${Math.round(days / 30)} months old`;
  } else {
    domainAgeDisplay.textContent = `${(days / 365).toFixed(1)} yrs`;
  }
  domainAgeCard.classList.remove("hidden");
  renderDomainReputationPill(days);
}

function renderDomainReputationPill(days) {
  const pill = document.getElementById("domain-reputation-pill");
  if (!pill) return;
  let label, tone;
  if (days == null || days < 0) {
    label = "Unknown"; tone = "warning";
  } else if (days >= 365) {
    label = "Established"; tone = "safe";
  } else if (days >= 90) {
    label = "Recent"; tone = "warning";
  } else {
    label = "New"; tone = "warning";
  }
  pill.textContent = label;
  pill.className = `domain-reputation-pill rep-${tone}`;
}

function renderIndicators(scanUrl, data, computedThreat) {
  const threat = computedThreat ?? data.threat_score ?? 0.5;
  const isHttps = scanUrl.startsWith("https://");
  const isHttp = scanUrl.startsWith("http://");

  const rows = [
    isHttps
      ? indicatorRow("check", "", "SSL / HTTPS", "Encrypted")
      : indicatorRow("cross", "", "SSL / HTTPS", isHttp ? "Insecure HTTP" : "Not Found"),
    data.verdict === "Limited Evidence"
      ? indicatorRow("warn", "", "Page Evidence", "Unavailable")
      : threat <= 0.3
      ? indicatorRow("check", "", "Suspicious Signals", "None")
      : threat <= 0.5
        ? indicatorRow("warn", "", "Suspicious Signals", "Review")
        : indicatorRow("cross", "", "Suspicious Signals", "High"),
  ];

  threatIndicators.innerHTML = rows.join("");
  // Stagger entrance animation per item
  threatIndicators.querySelectorAll(".indicator").forEach((el, i) => {
    el.style.animationDelay = `${i * 40}ms`;
  });
  threatIndicators.classList.remove("hidden");
}

function renderChecklist(rules) {
  checklistEl.innerHTML = "";
  const activeRules = [...(rules || [])]
    .filter(r => r.adjustment !== 0)
    .sort((a, b) => a.adjustment - b.adjustment)
    .slice(0, 6);

  if (!activeRules.length) {
    checklistEl.classList.add("hidden");
    return;
  }

  checklistEl.classList.remove("hidden");
  activeRules.forEach((rule, i) => {
    const safe = rule.adjustment <= 0;
    const li = document.createElement("li");
    li.className = "indicator";
    li.style.animationDelay = `${i * 40}ms`;
    const tone = safe ? "safe" : "danger";
    const paths = safe
      ? `<polyline points="20 6 9 17 4 12"/>`
      : `<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>`;
    li.innerHTML = `
      <svg class="indicator-icon tone-${tone}" width="13" height="13" viewBox="0 0 24 24"
        fill="none" stroke="currentColor" stroke-width="2.5"
        stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>
      <span class="indicator-label">${escapeHtml(rule.reason)}</span>`;
    checklistEl.appendChild(li);
  });
}

function showSellerTransparencyBadge(contact, scanStatus) {
  const existing = sellerInsightsBtn.querySelector(".seller-transparency-badge");
  if (existing) existing.remove();
  if (!contact) return "weak";

  const hasPhone = contact.contacts ? contact.contacts.some(c => c.validated && !c.conflict && ["phone", "whatsapp"].includes(c.channel)) : !!contact.has_phone;
  const hasEmail = (contact.emails?.length || 0) > 0;
  const hasReturn = !!contact.has_return_policy;
  const hasRefund = !!contact.has_refund_policy;
  const hasPrivacy = !!contact.has_privacy_policy;
  const hasTerms = !!contact.has_terms_conditions;
  const contactChannels = Number(hasPhone) + Number(hasEmail);          // 0, 1, or 2
  const policySignals = [hasReturn, hasRefund, hasPrivacy, hasTerms].filter(Boolean).length;
  const score = contactChannels + policySignals;

  /*  ── Transparency badge rules ──
   *  Strong   : needs ≥ 4 total signals AND both phone+email present
   *  Moderate : needs ≥ 2 total signals AND at least one of phone/email
   *  Weak     : everything else (incl. zero contact channels regardless of policies)
   *
   *  Key rule: if neither phone nor email is found, cap at Weak —
   *  policy pages alone don't prove the seller is reachable.
   */
  let tone, label, iconPath, level;
  if (scanStatus?.status === "partial" || contact.contacts?.some(c => c.conflict)) {
    tone = "warning"; label = "Incomplete"; level = "incomplete";
    iconPath = `<path d="M12 9v4m0 4h.01"/>`;
  } else if (contactChannels === 0) {
    // No direct contact channel → always Weak
    tone = "danger"; label = "Weak"; level = "weak";
    iconPath = `<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>`;
  } else if (score >= 4 && contactChannels === 2) {
    // Both phone & email + enough other signals → Strong
    tone = "safe"; label = "Strong"; level = "strong";
    iconPath = `<polyline points="20 6 9 17 4 12"/>`;
  } else if (score >= 2 && contactChannels >= 1) {
    // At least one contact channel + some other signals → Moderate
    tone = "warning"; label = "Moderate"; level = "moderate";
    iconPath = `<path d="M12 9v4m0 4h.01"/>`;
  } else {
    tone = "danger"; label = "Weak"; level = "weak";
    iconPath = `<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>`;
  }

  const badge = document.createElement("span");
  badge.className = `seller-transparency-badge ${tone}`;
  badge.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none"
    stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"
    aria-hidden="true">${iconPath}</svg> Seller Transparency – ${label}`;

  const container = sellerInsightsBtn.querySelector(".seller-tab-text-container");
  if (container) container.appendChild(badge);
  return level;
}

/* ── State setters ── */
function setIdle() {
  scoreEl.textContent = "--";
  scoreEl.style.color = "";
  const r = +ringProgress.getAttribute("r") || 42;
  const circ = 2 * Math.PI * r;
  ringProgress.style.strokeDasharray = circ;
  ringProgress.style.strokeDashoffset = circ;
  ringProgress.style.stroke = "var(--border-default)";
  riskText.textContent = "Ready to Scan";
  riskText.style.color = "";
  riskText.classList.remove("is-scanning");
  riskIcon.style.background = "";
  riskIcon.style.boxShadow = "";
  riskDescription.textContent = "";
  hideRecentScanLabel();
  threatIndicators.classList.add("hidden");
  threatIndicators.innerHTML = "";
  domainAgeCard.classList.add("hidden");
  checklistEl.classList.add("hidden");
  checklistEl.innerHTML = "";
  collapseAiSummary();
  threatExpl.classList.add("hidden");
  explanationText.textContent = "";
  state.aiSummary = null;
  state.aiSummaryRequest = null;
  collapseSellerInsights();
  sellerInsightsSection.classList.add("hidden");
  resultArea.classList.remove("compact");
  if (scanBtnTextEl) scanBtnTextEl.textContent = "Initiate Scan";
}

function setLoading() {
  scoreEl.innerHTML = '<span class="scan-dot">.</span><span class="scan-dot">.</span><span class="scan-dot">.</span>';
  scoreEl.style.color = "var(--color-text-muted)";
  riskText.textContent = "SCANNING...";
  riskText.style.color = "var(--color-ocean)";
  riskText.classList.add("is-scanning");
  riskDescription.textContent = "Analysing the URL. Please wait.";
  hideRecentScanLabel();
  threatIndicators.classList.add("hidden");
  threatIndicators.innerHTML = "";
  checklistEl.classList.add("hidden");
  checklistEl.innerHTML = "";
  domainAgeCard.classList.add("hidden");
  collapseAiSummary();
  threatExpl.classList.add("hidden");
  state.aiSummary = null;
  state.aiSummaryRequest = null;
  sellerInsightsSection.classList.add("hidden");
  collapseSellerInsights();
  sellerInsightsList.innerHTML = "";
  state.sellerInsightsLoadedFor = "";
  scanBtn.disabled = true;
  scanBtn.classList.add("scanning");
  sellerInsightsBtn.disabled = true;
  if (scanBtnTextEl) scanBtnTextEl.textContent = "Scanning...";
}

function setError(message) {
  scoreEl.textContent = "!";
  scoreEl.style.color = "var(--color-danger)";
  riskText.textContent = "ERROR";
  riskText.style.color = "var(--color-danger)";
  riskText.classList.remove("is-scanning");
  riskDescription.textContent = message;
  hideRecentScanLabel();
  riskIcon.style.background = "var(--color-danger)";
  riskIcon.style.boxShadow = "0 0 6px var(--shadow-danger)";
  scanBtn.disabled = false;
  scanBtn.classList.remove("scanning");
  sellerInsightsBtn.disabled = false;
  if (scanBtnTextEl) scanBtnTextEl.textContent = "Try Again";
}

function collapseSellerInsights() {
  sellerInsightsBtn.classList.remove("open");
  sellerInsightsBtn.setAttribute("aria-expanded", "false");
  sellerInsightsPanel.classList.remove("revealed");
  sellerInsightsPanel.classList.add("hidden");
}

function toggleHeaderMenu(event) {
  event.stopPropagation();
  const isHidden = headerMenuPanel.classList.toggle("hidden");
  headerMenuBtn.setAttribute("aria-expanded", String(!isHidden));
}

function closeHeaderMenu(event) {
  if (headerMenuPanel && !headerMenuPanel.classList.contains("hidden") && !headerMenuBtn.contains(event.target) && !headerMenuPanel.contains(event.target)) {
    headerMenuPanel.classList.add("hidden");
    headerMenuBtn.setAttribute("aria-expanded", "false");
  }
}

function applyAnalysis(data, scannedUrl, options = {}) {
  const oldBadge = sellerInsightsBtn.querySelector(".seller-transparency-badge");
  if (oldBadge) oldBadge.remove();
  state.lastAnalysis = data;
  state.lastScannedUrl = scannedUrl;
  state.sellerInsightsLoadedFor = "";
  sellerInsightsList.innerHTML = "";
  if (!options.keepAiSummary) {
    state.aiSummary = null;
    state.aiSummaryRequest = null;
    collapseAiSummary();
    explanationText.textContent = "";
  }

  const threat = typeof data.threat_score === "number"
    ? data.threat_score
    : typeof data.score === "number"
      ? Math.max(0, 1 - data.score / 100)
      : 0.5;


  animateRing(data.verdict === "Limited Evidence" ? 1 : threat);
  if (data.verdict === "Limited Evidence") {
    scoreEl.textContent = "--";
    scoreEl.style.color = "var(--color-text-muted)";
  }
  setVerdict(data.verdict ?? data.level, threat);
  renderDomainAge(data.domain_age_days ?? null);
  renderIndicators(scannedUrl, data, threat);
  renderChecklist(data.fired_rules || []);

  threatExpl.classList.remove("hidden");

  if (data.contact_signals?.uses_ecommerce || data.contact_signals?.scraped === false) {
    sellerInsightsSection.classList.remove("hidden");
    // Set favicon to scanned website's favicon
    try {
      const faviconDomain = new URL(scannedUrl.startsWith("http") ? scannedUrl : "https://" + scannedUrl).hostname;
      if (sellerFavicon) {
        sellerFavicon.src = `https://www.google.com/s2/favicons?sz=32&domain=${faviconDomain}`;
        sellerFavicon.onerror = () => { sellerFavicon.src = "../assets/icons/icon16.png"; };
      }
    } catch { if (sellerFavicon) sellerFavicon.src = "../assets/icons/icon16.png"; }
  } else {
    sellerInsightsSection.classList.add("hidden");
    collapseSellerInsights();
  }

  resultArea.classList.add("compact");
  scanBtn.disabled = false;
  scanBtn.classList.remove("scanning");
  sellerInsightsBtn.disabled = false;
  if (scanBtnTextEl) scanBtnTextEl.textContent = "Scan Again";
  if (options.fromCache) showRecentScanLabel(options.savedAt);
  else hideRecentScanLabel();
}

/* ── Network ── */
async function postJson(path, payload) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(path === "/seller-insights" ? 45000 : 30000),
  });
  if (!res.ok) {
    let message = `Server responded with HTTP ${res.status}`;
    try {
      const err = await res.json();
      if (err.error) message = err.error;
    } catch { }
    throw new Error(message);
  }
  const data = await res.json();
  if (path === "/seller-insights" && data.analysis?.extraction_version !== "seller-v2") {
    throw new Error("Seller Insights is waiting for a service update. Please try again later.");
  }
  return data;
}

async function postJsonCached(path, payload, ttlMs) {
  const cachedEntry = getCachedResponse(path, payload);
  if (cachedEntry) {
    return { data: cachedEntry.data, fromCache: true, savedAt: cachedEntry.savedAt };
  }
  const data = await postJson(path, payload);
  setCachedResponse(path, payload, data, ttlMs);
  return { data, fromCache: false, savedAt: null };
}

function clearCachedResponses(path, url) {
  const cache = pruneExpiredCacheEntries(readScanCache());
  const prefix = `${path}::${url}`;
  for (const key of Object.keys(cache)) {
    if (key === prefix || key.startsWith(`${prefix}::`)) delete cache[key];
  }
  writeScanCache(cache);
}

function getSelectedUrl() {
  const typedValue = (urlDisplay.value || "").trim();
  if (!typedValue) return urlForScan(state.currentTabUrl);

  const currentPresented = state.currentTabUrl ? presentUrl(state.currentTabUrl) : "";
  const lastPresented = state.lastScannedUrl ? presentUrl(state.lastScannedUrl) : "";

  if (currentPresented && typedValue === currentPresented) return urlForScan(state.currentTabUrl);
  if (lastPresented && typedValue === lastPresented) return urlForScan(state.lastScannedUrl);
  return urlForScan(typedValue);
}

async function getTrustSignals(url) {
  if (state.currentTabId == null) return {};
  try {
    const result = await chrome.runtime.sendMessage({ type: "GET_TRUST_SIGNALS", tabId: state.currentTabId, url });
    return result && !result.error ? result : {};
  } catch { return {}; }
}

async function runScan() {
  const scanUrl = getSelectedUrl();
  if (!scanUrl) { setError("Enter a valid URL to scan."); return; }
  if (/^(chrome|about|edge|chrome-extension):/i.test(scanUrl)) {
    setError("Browser internal pages cannot be scanned.");
    return;
  }

  const revision = ++state.scanRevision;
  state.activeScanUrl = scanUrl;
  setLoading();
  urlDisplay.value = presentUrl(scanUrl);

  try {
    for (const path of ["/predict", "/seller-insights", "/explain"]) clearCachedResponses(path, scanUrl);
    const signals = await getTrustSignals(scanUrl);
    const response = await postJsonCached("/predict", { url: scanUrl, signals }, SCAN_CACHE_TTL_MS);
    if (state.scanRevision !== revision) return;
    applyAnalysis(response.data, scanUrl, response);
  } catch (err) {
    if (state.scanRevision !== revision) return;
    setError(`Could not reach backend: ${err.message}`);
  }
}

/* ── Seller panel ── */
function renderSellerLoading() {
  sellerInsightsList.innerHTML = `
    <div class="seller-item">
      <div class="seller-icon safe">${ICONS.phone}</div>
      <div class="seller-main">
        <div class="seller-label">Contact</div>
        <div class="seller-value retrieving">Scraping contact channels</div>
      </div>
    </div>
    <div class="seller-item">
      <div class="seller-icon safe">${ICONS.email}</div>
      <div class="seller-main">
        <div class="seller-label">Mail</div>
        <div class="seller-value retrieving">Checking seller inbox details</div>
      </div>
    </div>`;
}

function makeIconButton(kind, payload, title) {
  const button = document.createElement("button");
  button.className = `icon-button ${kind}`;
  button.type = "button";
  button.dataset.payload = payload;
  button.dataset.kind = kind;
  button.innerHTML = kind === "copy" ? ICONS.copy : ICONS.policy;
  button.title = title || (kind === "copy" ? "Copy" : "Open link");
  button.setAttribute("aria-label", button.title);
  return button;
}

function badgeMarkup(tone, text) {
  return `<span class="seller-badge ${tone}">${tone === "safe" ? ICONS.check : ICONS.warning} ${text}</span>`;
}

function createSellerItem({ icon, iconTone = "", label, value, valueHtml, badge, metaHtml = "", copyValue, linkUrl, linkTitle, alternativeLinks = [], inlineActions = false, allowLink = true }) {
  const row = document.createElement("div");
  row.className = "seller-item";
  const plainValue = valueHtml ? "" : (value || "");
  const isMissing = plainValue === "Not found";
  const actionsMarkup = '<div class="seller-actions"></div>';
  row.innerHTML = `
    <div class="seller-icon ${iconTone}">${icon}</div>
    <div class="seller-main">
      <div class="seller-label-row">
        <div class="seller-label">${escapeHtml(label)}</div>
        ${badge ? badgeMarkup(badge.tone, badge.text) : ""}
        ${metaHtml}
        ${inlineActions ? actionsMarkup : ""}
      </div>
      ${valueHtml || plainValue ? `<div class="seller-value ${isMissing ? "missing" : ""}">${valueHtml || escapeHtml(plainValue)}</div>` : ""}
    </div>
    ${inlineActions ? "" : actionsMarkup}`;
  const actions = row.querySelector(".seller-actions");
  if (copyValue) actions.appendChild(makeIconButton("copy", copyValue));
  if (allowLink && linkUrl) actions.appendChild(makeIconButton("external", linkUrl, linkTitle || `Open ${label}`));
  if (allowLink) for (const [index, source] of alternativeLinks.entries()) {
    actions.appendChild(makeIconButton("external", source.source_url, `Open other ${label} source ${index + 1}`));
  }
  return row;
}

// Canonical values from extraction keep country codes and extensions distinct.
function groupSellerContacts(records) {
  const normalize = value => (value || "").replace(/^tel:/i, "")
    .replace(/[\s().-]/g, "").replace(/^00/, "+")
    .replace(/(?:ext\.?|x)(\d+)$/i, ";ext=$1").replace(/;;ext=/i, ";ext=");
  // A countryless legacy value can match a published international value
  // only by its complete digits, never a last-N-digit suffix guess.
  const international = new Set(records.map(r => normalize(r.value)).filter(v => v.startsWith("+")));
  const groups = new Map();
  for (const record of records) {
    let key = normalize(record.value);
    if (!key.startsWith("+") && international.has("+" + key)) key = "+" + key;
    if (!key) continue;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ ...record, value: key,
      channel: ["mobile", "telephone", "tel"].includes(record.channel) ? "phone" : record.channel });
  }
  return [...groups.values()].map(records => {
    const whatsappOnly = records.some(record => record.whatsapp_only);
    const usable = records.filter(record => !(whatsappOnly && record.channel === "phone"));
    return { records: usable, whatsappOnly };
  });
}

function appendContactGroup(rows, singular, plural) {
  sellerInsightsList.appendChild(rows[0]);
  if (rows.length === 1) return;
  const other = document.createElement("details");
  other.className = "seller-contact-more";
  const toggle = document.createElement("summary");
  const count = rows.length - 1;
  toggle.innerHTML = `<span class="seller-contact-expand">Show ${count} more ${count === 1 ? singular : plural}</span>
    <span class="seller-contact-collapse">Show fewer ${plural}</span>`;
  other.appendChild(toggle);
  for (const row of rows.slice(1)) other.appendChild(row);
  sellerInsightsList.appendChild(other);
}

function renderSellerPhones(contact) {
  const contacts = contact.contacts?.length ? contact.contacts : [
    ...(contact.phone_numbers || []).map(value => ({ value, display: value, channel: "phone", purpose: "support" })),
    ...(contact.whatsapp_numbers || []).map(value => ({ value, display: value, channel: "whatsapp", purpose: "support" })),
  ];
  const rows = [];
  for (const { records, whatsappOnly } of groupSellerContacts(contacts)) {
    if (!records.length) continue;
    const record = records[0];
    const channels = [...new Set(records.map(r => r.channel))];
    const roles = [...new Set(records.map(r => ({ exchange: "Exchange", returns: "Returns", sales: "Sales",
      partnerships: "Partnerships", support: "Support" }[r.purpose] || "Contact")))];
    const channel = whatsappOnly ? "WhatsApp only" : channels.map(c => c === "whatsapp" ? "WhatsApp" : c === "fax" ? "Fax" : "Phone").join(" / ");
    const notes = [...new Set(records.map(r => r.hours).filter(Boolean))];
    if (records.some(r => r.conflict)) notes.push("Visible number differs from the site's phone link");
    if (records.some(r => r.validated === false)) notes.push("Country could not be confirmed");
    const row = createSellerItem({
      icon: channels.includes("whatsapp") ? ICONS.whatsapp : ICONS.phone,
      label: `${roles.join(" / ")} - ${channel}`,
      valueHtml: escapeHtml(record.display || record.value)
        + (notes.length ? `<small class="seller-evidence-note">${escapeHtml(notes.join(". "))}</small>` : ""),
      copyValue: record.value,
    });
    const actions = row.querySelector(".seller-actions");
    for (const channel of channels) {
      const target = records.find(r => r.channel === channel && r.validated !== false);
      if (!target) continue;
      if (channel === "whatsapp" && /^\+\d+$/.test(target.value))
        actions.appendChild(makeIconButton("external", `https://wa.me/${target.value.slice(1)}`, "Open WhatsApp"));
      else if (channel === "phone" && /^\+\d+(;ext=\d+)?$/.test(target.value))
        actions.appendChild(makeIconButton("external", `tel:${target.value}`, "Call number"));
    }
    rows.push(row);
  }
  appendContactGroup(rows.length ? rows : [createSellerItem({
    icon: ICONS.phone, label: "Phone / WhatsApp", value: "Not found",
  })], "number", "numbers");
}

function renderSellerEmails(contact) {
  const normaliseEmail = email => typeof email === "string" ? email.trim().toLowerCase() : "";
  const records = contact.email_records || [];
  const evaluations = contact.email_evaluations || [];
  const emails = [...new Set([...(contact.emails || []), ...records.map(record => record.value)].map(normaliseEmail))]
    .filter(email => /^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$/i.test(email));
  const rows = emails.map(email => {
    const evaluation = evaluations.find(item => normaliseEmail(item.email) === email);
    const record = records.find(item => normaliseEmail(item.value) === email);
    const label = {
      privacy: "Mail - Privacy contact", grievance: "Mail - Grievance contact", press: "Mail - Press",
      partnerships: "Mail - Partnerships", legal: "Mail - Legal", sales: "Mail - Sales", support: "Mail - Support",
    }[record?.purpose] || "Mail";
    return createSellerItem({
      icon: ICONS.email, iconTone: evaluation?.tone === "safe" ? "safe" : "", label, value: email,
      badge: evaluation?.tone === "safe" ? { tone: "safe", text: escapeHtml(evaluation.label) } : null,
      copyValue: email,
      linkUrl: `https://mail.google.com/mail/?view=cm&fs=1&to=${encodeURIComponent(email)}`,
      linkTitle: "Compose in Gmail",
    });
  });
  appendContactGroup(rows.length ? rows : [createSellerItem({
    icon: ICONS.email, label: "Mail", value: "Not found",
  })], "email", "emails");
}

const commercePolicies = { return: "Returns", exchange: "Exchanges", refund: "Refunds" };

function legacyPolicyCards(analysis) {
  const groups = new Map();
  for (const kind of Object.keys(commercePolicies)) {
    const document = analysis.policies?.[kind];
    if (document && !["extracted", "structured_only"].includes(document.status)) continue;
    const summary = analysis.policy_summaries?.[`${kind}_policy`];
    if (typeof summary !== "string" || !summary.trim()) continue;
    const url = document?.source_url || analysis.contact_signals?.[`${kind}_policy_url`];
    const group = groups.get(url || kind) || { kinds: [], points: [], source_urls: url ? [url] : [] };
    group.kinds.push(kind);
    group.points.push(...summaryLines(summary));
    groups.set(url || kind, group);
  }
  return [...groups.values()].map(group => {
    if (group.kinds.length === 1) return group;
    const topics = [[], [], [], []];
    for (const point of new Set(group.points)) {
      const topic = /\b(?:fee|charge|deduct)\w*\b|[?$??]/i.test(point) ? 0
        : /\b(?:return|exchange) window\b|\bwithin\s+\d+/i.test(point) ? 1
        : /\b(?:store credit|original payment|refund method|bank account)\b/i.test(point) ? 2 : 3;
      topics[topic].push(point);
    }
    return { ...group, points: topics.map(points => points.reduce((line, point) =>
      line.length + point.length >= 450 ? line : [line, point].filter(Boolean).join(" "), "")).filter(Boolean) };
  });
}

function renderSellerPolicies(analysis, contact) {
  const labels = { return: "Return Policy", exchange: "Exchange Policy", refund: "Refund Policy",
    shipping: "Shipping Policy", cancellation: "Cancellation Policy", privacy: "Privacy Policy", terms: "Terms & Conditions" };
  const cards = Array.isArray(analysis.policy_cards) ? analysis.policy_cards : legacyPolicyCards(analysis);
  const shown = new Set();
  for (const card of cards) {
    const kinds = (card.kinds || []).filter(kind => Object.hasOwn(commercePolicies, kind));
    if (!kinds.length || !Array.isArray(card.points)) continue;
    const label = kinds.length === 1 ? labels[kinds[0]]
      : `${kinds.slice(0, -1).map(kind => commercePolicies[kind]).join(", ")} & ${commercePolicies[kinds.at(-1)]}`;
    const urls = new Set(card.source_urls || []);
    for (const kind of kinds) {
      shown.add(kind);
      const document = analysis.policies?.[kind];
      if (document?.source_url) urls.add(document.source_url);
      for (const source of document?.alternative_sources || []) {
        if (source.source_url) urls.add(source.source_url);
      }
    }
    const [linkUrl, ...otherUrls] = urls;
    sellerInsightsList.appendChild(createSellerItem({
      icon: ICONS.policy, label, valueHtml: renderSummaryPoints(card.points, true), linkUrl, inlineActions: true,
      alternativeLinks: otherUrls.slice(0, 3).map(source_url => ({ source_url })),
    }));
  }

  for (const [kind, label] of Object.entries(labels)) {
    if (shown.has(kind)) continue;
    const document = analysis.policies?.[kind];
    const url = document?.source_url || contact[kind === "terms" ? "terms_conditions_url" : `${kind}_policy_url`];
    if (!url) continue;
    const alternativeLinks = (document?.alternative_sources || [])
      .filter(source => source.source_url && source.source_url !== url).slice(0, 3);
    const value = document?.status === "discovered" ? "Linked by store · contents unverified" : undefined;
    sellerInsightsList.appendChild(createSellerItem({ icon: ICONS.policy, label, value, linkUrl: url, alternativeLinks, inlineActions: true }));
  }
}

function renderSellerInsights(response) {
  const analysis = response.analysis || state.lastAnalysis;
  const contact = analysis.contact_signals || {};
  const meta = analysis.domain_metadata || {};

  sellerInsightsList.innerHTML = "";
  renderSellerPhones(contact);
  renderSellerEmails(contact);
  renderSellerPolicies(analysis, contact);

  const registeredTo = meta.organization || meta.registrant_name || "Unknown";
  const location = meta.country && !meta.registrant_is_proxy ? ` (${meta.country})` : "";
  sellerInsightsList.appendChild(createSellerItem({
    icon: ICONS.whois, label: meta.registrant_is_proxy ? "WHOIS Privacy Proxy" : "WHOIS Registrant", value: `${registeredTo}${location}`,
  }));

  sellerInsightsList.querySelectorAll(".seller-item").forEach((el, i) => {
    el.style.animationDelay = `${i * 35}ms`;
  });
}

function handleSellerListAction(event) {
  const button = event.target.closest(".icon-button");
  if (!button) return;
  const { kind, payload } = button.dataset;
  if (kind === "copy") {
    navigator.clipboard.writeText(payload).then(() => {
      button.classList.add("copied");
      button.innerHTML = ICONS.check;
      clearTimeout(copiedButtonTimer);
      copiedButtonTimer = setTimeout(() => {
        button.classList.remove("copied");
        button.innerHTML = ICONS.copy;
      }, 850);
    }).catch(() => { });
  } else if (kind === "external") {
    try {
      const target = new URL(payload);
      const web = ["https:", "http:"].includes(target.protocol) && !target.username && !target.password;
      if (web || /^tel:\+\d+(;ext=\d+)?$/.test(payload)) chrome.tabs.create({ url: payload });
    } catch { /* Ignore malformed or unsafe destinations. */ }
  }
}

async function toggleSellerInsights() {
  if (!state.lastScannedUrl) return;
  const willOpen = sellerInsightsPanel.classList.contains("hidden");
  if (!willOpen) { collapseSellerInsights(); return; }

  sellerInsightsBtn.classList.add("open");
  sellerInsightsBtn.setAttribute("aria-expanded", "true");
  sellerInsightsPanel.classList.remove("hidden");
  sellerInsightsPanel.classList.remove("revealed");
  requestAnimationFrame(() => sellerInsightsPanel.classList.add("revealed"));

  if (state.sellerInsightsLoadedFor === state.lastScannedUrl) return;

  sellerInsightsList.innerHTML = "";
  renderSellerLoading();
  const fetchUrl = state.lastScannedUrl;
  const revision = state.scanRevision;
  try {
    const signals = await getTrustSignals(fetchUrl);
    const response = await postJsonCached("/seller-insights", { url: fetchUrl, signals }, DETAIL_CACHE_TTL_MS);

    if (state.lastScannedUrl !== fetchUrl || state.scanRevision !== revision) return;

    if (response.data.analysis) {
      applyAnalysis(response.data.analysis, fetchUrl, { keepAiSummary: true });
      setCachedResponse("/predict", { url: fetchUrl }, response.data.analysis, SCAN_CACHE_TTL_MS);
      sellerInsightsBtn.classList.add("open");
      sellerInsightsBtn.setAttribute("aria-expanded", "true");
      sellerInsightsPanel.classList.remove("hidden");
      sellerInsightsPanel.classList.add("revealed");
    }
    renderSellerInsights(response.data);
    showSellerTransparencyBadge(state.lastAnalysis?.contact_signals || {}, state.lastAnalysis?.scan_status);

    state.sellerInsightsLoadedFor = state.lastScannedUrl;
  } catch (err) {
    if (state.lastScannedUrl !== fetchUrl || state.scanRevision !== revision) return;
    sellerInsightsList.innerHTML = `<div class="seller-item">
      <div class="seller-icon">${ICONS.policy}</div>
      <div class="seller-main">
        <div class="seller-label">Status</div>
        <div class="seller-value">${escapeHtml(err.message)}</div>
      </div></div>`;
  }
}

/* ── AI Summary ── */
function collapseAiSummary() {
  if (aiSummaryBtn) {
    aiSummaryBtn.classList.remove("open");
    aiSummaryBtn.setAttribute("aria-expanded", "false");
  }
  if (aiSummaryPanel) {
    aiSummaryPanel.classList.remove("revealed");
    aiSummaryPanel.classList.add("hidden");
  }
}

function renderAiSummary(summary) {
  const hostname = new URL(state.lastScannedUrl).hostname.replace(/^www\./, "");
  const links = [];
  for (const source of Array.isArray(summary.sources) ? summary.sources : []) {
    if (!source || typeof source.label !== "string") continue;
    try {
      const url = new URL(source.url);
      if (["http:", "https:"].includes(url.protocol) && !url.username && !url.password
          && url.hostname.replace(/^www\./, "") === hostname) {
        links.push(`<a href="${escapeHtml(url.href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(source.label)}</a>`);
      }
    } catch { /* Skip malformed evidence links. */ }
  }
  const explanation = typeof summary.explanation === "string" ? summary.explanation.trim() : "";
  const points = renderSummaryPoints(explanation || "No findings available.");
  explanationText.innerHTML = points + (links.length
    ? `<div class="explanation-sources" aria-label="Sources">${links.join("")}</div>` : "");
}

async function toggleAiSummary() {
  if (!state.lastAnalysis || !state.lastScannedUrl) return;
  const willOpen = aiSummaryPanel.classList.contains("hidden");
  if (!willOpen) {
    collapseAiSummary();
    return;
  }

  aiSummaryBtn.classList.add("open");
  aiSummaryBtn.setAttribute("aria-expanded", "true");
  aiSummaryPanel.classList.remove("hidden");
  aiSummaryPanel.classList.remove("revealed");
  requestAnimationFrame(() => aiSummaryPanel.classList.add("revealed"));

  if (state.aiSummary) {
    renderAiSummary(state.aiSummary);
    return;
  }
  if (state.aiSummaryRequest) return;

  explanationText.textContent = "Checking public pages…";
  const pending = { url: state.lastScannedUrl, revision: state.scanRevision };
  state.aiSummaryRequest = pending;
  const isCurrent = () => state.aiSummaryRequest === pending &&
    state.lastScannedUrl === pending.url && state.scanRevision === pending.revision;
  try {
    const signals = await getTrustSignals(pending.url);
    if (!isCurrent()) return;
    const response = await postJsonCached("/explain", { url: pending.url, signals }, SCAN_CACHE_TTL_MS);
    if (!isCurrent()) return;
    state.aiSummary = response.data;
    renderAiSummary(state.aiSummary);
  } catch {
    if (isCurrent()) explanationText.textContent = "Failed to generate AI summary.";
  } finally {
    if (state.aiSummaryRequest === pending) state.aiSummaryRequest = null;
  }
}

async function hydrateCurrentTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    state.currentTabUrl = tab?.url || "";
    state.currentTabId = tab?.id ?? null;
    if (state.currentTabUrl
      && !/^chrome:|^about:|^edge:|^chrome-extension:/i.test(state.currentTabUrl)
      && !urlDisplay.value.trim()) {
      urlDisplay.value = presentUrl(state.currentTabUrl);
    }
  } catch { state.currentTabUrl = ""; }
}

async function restoreRecentScanForCurrentTab() {
  if (!state.currentTabUrl
    || /^(chrome|about|edge|chrome-extension):/i.test(state.currentTabUrl)) return;

  const scanUrl = urlForScan(state.currentTabUrl);
  if (!scanUrl) return;

  const cachedEntry = getCachedResponse("/predict", { url: scanUrl });
  if (!cachedEntry?.data) {
    try {
      const entry = await chrome.runtime.sendMessage({ type: "GET_RECENT_SCAN", tabId: state.currentTabId, url: scanUrl });
      if (entry?.analysis && state.scanRevision === 0) {
        applyAnalysis(entry.analysis, scanUrl, { fromCache: true, savedAt: entry.savedAt });
      }
    } catch { }
    return;
  }

  urlDisplay.value = presentUrl(state.currentTabUrl);
  applyAnalysis(cachedEntry.data, cachedEntry.data.url || scanUrl, {
    fromCache: true,
    savedAt: cachedEntry.savedAt,
  });
}

/* ── Bootstrap ── */
document.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("extension-version").textContent = `ThreatLens v${chrome.runtime.getManifest().version}`;
  loadThemePreference();
  setIdle();
  await hydrateCurrentTab();
  await restoreRecentScanForCurrentTab();

  fullUrlToggle.addEventListener("change", () => {
    updateScanModeLabel();
    const sourceUrl = resolveDisplaySource(urlDisplay.value || state.currentTabUrl);
    if (sourceUrl) urlDisplay.value = presentUrl(sourceUrl);
  });

  urlDisplay.addEventListener("keydown", e => { if (e.key === "Enter") runScan(); });
  scanBtn.addEventListener("click", runScan);
  sellerInsightsBtn.addEventListener("click", toggleSellerInsights);
  if (aiSummaryBtn) aiSummaryBtn.addEventListener("click", toggleAiSummary);
  if (headerMenuBtn) headerMenuBtn.addEventListener("click", toggleHeaderMenu);
  document.addEventListener("click", closeHeaderMenu);
  themeToggle.addEventListener("click", toggleTheme);
  updateScanModeLabel();
  sellerInsightsList.addEventListener("click", handleSellerListAction);

  if (headerMenuPanel) {
    headerMenuPanel.addEventListener("click", e => {
      const supportBtnClick = e.target.closest("#support-menu-btn");
      if (supportBtnClick) {
        e.preventDefault();
        e.stopPropagation();
        const isHidden = supportSubmenu.classList.toggle("hidden");
        supportMenuBtn.setAttribute("aria-expanded", String(!isHidden));
        return;
      }

      const emailItem = e.target.closest("[data-email]");
      if (emailItem) {
        e.preventDefault();
        const email = emailItem.dataset.email;
        navigator.clipboard.writeText(email).catch(() => { });
        chrome.tabs.create({ url: `https://mail.google.com/mail/?view=cm&fs=1&to=${email}` });
      }
    });
  }

  // Cursor glow tracking
  const cursorGlow = document.getElementById("cursor-glow");
  const containerEl = document.querySelector(".container");
  if (cursorGlow && containerEl) {
    containerEl.addEventListener("mousemove", e => {
      cursorGlow.style.left = e.clientX + "px";
      cursorGlow.style.top = e.clientY + "px";
    });
  }
});
