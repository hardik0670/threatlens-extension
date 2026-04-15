const USE_LOCAL_BACKEND = false;
const API_BASE = USE_LOCAL_BACKEND
  ? "http://127.0.0.1:5000"
  : "https://threatlens-api.vercel.app";

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
let aiTypingTimer = null;
const THEME_STORAGE_KEY = "threatlens-theme";
const SCAN_CACHE_STORAGE_KEY = "threatlens-scan-cache";
const SCAN_CACHE_TTL_MS = 5 * 60 * 1000;
const DETAIL_CACHE_TTL_MS = 10 * 60 * 1000;

const C = {
  safe: { color: "var(--color-success)", shadow: "var(--shadow-success)" },
  medium: { color: "var(--color-warning)", shadow: "var(--shadow-warning)" },
  high: { color: "var(--color-danger)", shadow: "var(--shadow-danger)" },
};

const state = {
  currentTabUrl: "",
  lastScannedUrl: "",
  lastAnalysis: null,
  sellerInsightsLoadedFor: "",
  pendingExplanation: "",
  aiSummaryRevealed: false,
};

const ICONS = {
  phone: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.8 19.8 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.08 4.18 2 2 0 0 1 4.06 2h3a2 2 0 0 1 2 1.72c.12.9.33 1.77.62 2.62a2 2 0 0 1-.45 2.11L8 9.91a16 16 0 0 0 6.09 6.09l1.46-1.23a2 2 0 0 1 2.11-.45c.85.29 1.72.5 2.62.62A2 2 0 0 1 22 16.92z"></path></svg>`,
  whatsapp: `<svg width="13" height="13" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M16 3C8.82 3 3 8.69 3 15.7c0 2.47.74 4.88 2.13 6.92L3.9 29l6.6-1.72A13.2 13.2 0 0 0 16 28.4c7.18 0 13-5.69 13-12.7S23.18 3 16 3Z" fill="#4ED46B"/><path d="M10.64 25.21l.42-2.46-.17-.26a9.49 9.49 0 0 1-1.49-5.11c0-5.19 4.27-9.41 9.53-9.41 2.55 0 4.95.98 6.75 2.76a9.3 9.3 0 0 1 2.79 6.66c0 5.19-4.28 9.41-9.54 9.41a9.7 9.7 0 0 1-4.83-1.29l-.28-.16-3.18.86Z" fill="white"/><path d="M13.42 11.9c-.18-.41-.37-.42-.55-.43h-.47c-.16 0-.41.06-.63.29-.22.22-.85.82-.85 2 0 1.18.87 2.32.99 2.48.12.16 1.68 2.67 4.16 3.63 2.05.79 2.47.63 2.91.59.44-.04 1.42-.58 1.62-1.14.2-.56.2-1.05.14-1.14-.06-.09-.22-.14-.47-.27-.24-.13-1.42-.72-1.64-.8-.22-.08-.38-.12-.54.12-.16.24-.62.8-.76.96-.14.16-.28.18-.52.06-.24-.13-1.02-.37-1.95-1.17-.72-.63-1.2-1.4-1.34-1.64-.14-.24-.02-.37.11-.5.11-.11.24-.28.36-.42.12-.14.16-.24.24-.4.08-.16.04-.31-.02-.44-.06-.13-.55-1.39-.77-1.89Z" fill="#4ED46B"/></svg>`,
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
  return `${path}::${payload?.url || ""}`;
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
  const escaped = escapeHtml(text || "");
  if (!escaped) return "";
  const patterns = [
    /\bonly\s+(?:till|until|within)\s+\d+\s*(?:business\s+)?(?:day|days|week|weeks|month|months)\b/gi,
    /\bwithin\s+\d+\s*(?:business\s+)?(?:day|days|week|weeks|month|months)\b/gi,
    /\b\d+\s*(?:business\s+)?(?:day|days|week|weeks|month|months)\b/gi,
    /\b(?:rs\.?|inr)\s*\d+\b/gi,
    /\b\d+\s*rupees?\b/gi,
    /\b(?:non-refundable|not refundable|non returnable|non-returnable|final sale|store credit only|exchange only)\b/gi,
    /\boriginal payment method\b/gi,
    /\bstore credit\b/gi,
    /\bbank transfer\b/gi,
    /\bupi details\b/gi,
    /\breplacement\b/gi,
  ];
  let output = escaped;
  patterns.forEach(p => {
    output = output.replace(p, m => `<span class="policy-emphasis">${m}</span>`);
  });
  return output;
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
  const col = pal(threat);
  const label = verdict || (threat <= 0.3 ? "Safe" : threat <= 0.5 ? "Medium Risk" : "High Risk");
  riskText.textContent = label.toUpperCase();
  riskText.style.color = col.color;
  riskText.classList.remove("is-scanning");
  riskIcon.style.background = col.color;
  riskIcon.style.boxShadow = `0 0 6px ${col.shadow}`;
  riskDescription.textContent = "";
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
    label = "Good"; tone = "safe";
  } else if (days >= 90) {
    label = "Risky"; tone = "warning";
  } else {
    label = "Suspicious"; tone = "danger";
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
    threat <= 0.3
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
      <span class="indicator-label">${rule.reason}</span>`;
    checklistEl.appendChild(li);
  });
}

function showSellerTransparencyBadge(contact) {
  const existing = sellerInsightsBtn.querySelector(".seller-transparency-badge");
  if (existing) existing.remove();
  if (!contact) return;

  const hasPhone = (contact.phone_numbers?.length || 0) > 0;
  const hasEmail = (contact.emails?.length || 0) > 0;
  const hasReturn = !!contact.return_policy_url;
  const hasRefund = !!contact.refund_policy_url;
  const hasPrivacy = !!contact.privacy_policy_url;
  const hasTerms = !!contact.terms_conditions_url;
  const score = [hasPhone, hasEmail, hasReturn, hasRefund, hasPrivacy, hasTerms].filter(Boolean).length;

  let tone, label, iconPath;
  if (score >= 4) {
    tone = "safe"; label = "Strong";
    iconPath = `<polyline points="20 6 9 17 4 12"/>`;
  } else if (score >= 2) {
    tone = "warning"; label = "Moderate";
    iconPath = `<path d="M12 9v4m0 4h.01"/>`;
  } else {
    tone = "danger"; label = "Weak";
    iconPath = `<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>`;
  }

  const badge = document.createElement("span");
  badge.className = `seller-transparency-badge ${tone}`;
  badge.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none"
    stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"
    aria-hidden="true">${iconPath}</svg> Seller Tranparency – ${label}`;

  const container = sellerInsightsBtn.querySelector(".seller-tab-text-container");
  if (container) container.appendChild(badge);
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
  state.pendingExplanation = "";
  state.aiSummaryRevealed = false;
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
  state.pendingExplanation = "";
  state.aiSummaryRevealed = false;
  sellerInsightsSection.classList.add("hidden");
  collapseSellerInsights();
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
  state.lastAnalysis = data;
  state.lastScannedUrl = scannedUrl;
  state.sellerInsightsLoadedFor = "";
  state.pendingExplanation = data.explanation || "";
  state.aiSummaryRevealed = false;

  const threat = typeof data.threat_score === "number"
    ? data.threat_score
    : typeof data.score === "number"
      ? Math.max(0, 1 - data.score / 100)
      : 0.5;

  animateRing(threat);
  setVerdict(data.verdict ?? data.level, threat);
  renderDomainAge(data.domain_age_days ?? null);
  renderIndicators(scannedUrl, data, threat);
  renderChecklist(data.fired_rules || []);

  // Keep AI summary section closed; store the text for lazy reveal
  collapseAiSummary();
  explanationText.textContent = "";
  if (state.pendingExplanation) {
    threatExpl.classList.remove("hidden");
  } else {
    threatExpl.classList.add("hidden");
  }

  if (data.contact_signals?.uses_ecommerce) {
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
  });
  if (!res.ok) {
    let message = `Server responded with HTTP ${res.status}`;
    try {
      const err = await res.json();
      if (err.error) message = err.error;
    } catch { }
    throw new Error(message);
  }
  return res.json();
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

function clearCachedResponse(path, payload) {
  const cache = pruneExpiredCacheEntries(readScanCache());
  const key = buildCacheKey(path, payload);
  if (cache[key]) { delete cache[key]; writeScanCache(cache); }
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

async function runScan() {
  const scanUrl = getSelectedUrl();
  if (!scanUrl) { setError("Enter a valid URL to scan."); return; }
  if (/^(chrome|about|edge|chrome-extension):/i.test(scanUrl)) {
    setError("Browser internal pages cannot be scanned.");
    return;
  }

  setLoading();
  urlDisplay.value = presentUrl(scanUrl);

  try {
    clearCachedResponse("/predict", { url: scanUrl });
    clearCachedResponse("/seller-insights", { url: scanUrl });
    const response = await postJsonCached("/predict", { url: scanUrl }, SCAN_CACHE_TTL_MS);
    applyAnalysis(response.data, response.data.url || scanUrl, response);
  } catch (err) {
    setError(`Could not reach backend: ${err.message}`);
  }
}

/* ── Seller panel ── */
function renderSellerLoading() {
  sellerInsightsList.innerHTML = `
    <div class="seller-item">
      <div class="seller-icon safe">${ICONS.phone}</div>
      <div class="seller-main">
        <div class="seller-label">Mobile</div>
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

function makeIconButton(kind, payload) {
  const button = document.createElement("button");
  button.className = `icon-button ${kind}`;
  button.type = "button";
  button.dataset.payload = payload;
  button.dataset.kind = kind;
  button.innerHTML = kind === "copy" ? ICONS.copy : ICONS.policy;
  button.title = kind === "copy" ? "Copy" : "Open link";
  return button;
}

function badgeMarkup(tone, text) {
  return `<span class="seller-badge ${tone}">${tone === "safe" ? ICONS.check : ICONS.warning} ${text}</span>`;
}

function createSellerItem({ icon, iconTone = "", label, value, valueHtml, badge, metaHtml = "", copyValue, linkUrl, allowLink = true }) {
  const row = document.createElement("div");
  row.className = "seller-item";
  const plainValue = valueHtml ? "" : (value || "");
  const isMissing = (!plainValue && !valueHtml) || plainValue === "Not found";
  row.innerHTML = `
    <div class="seller-icon ${iconTone}">${icon}</div>
    <div class="seller-main">
      <div class="seller-label-row">
        <div class="seller-label">${label}</div>
        ${badge ? badgeMarkup(badge.tone, badge.text) : ""}
        ${metaHtml}
      </div>
      <div class="seller-value ${isMissing ? "missing" : ""}">${valueHtml || escapeHtml(plainValue)}</div>
    </div>
    <div class="seller-actions"></div>`;
  const actions = row.querySelector(".seller-actions");
  if (copyValue) actions.appendChild(makeIconButton("copy", copyValue));
  if (allowLink && linkUrl) actions.appendChild(makeIconButton("external", linkUrl));
  return row;
}

function renderSellerInsights(response) {
  const analysis = response.analysis || state.lastAnalysis;
  const contact = analysis.contact_signals || {};
  const meta = analysis.domain_metadata || {};
  const policySummaries = analysis.policy_summaries || {};

  sellerInsightsList.innerHTML = "";

  const rawPhone = contact.phone_numbers?.[0] || "";
  const rawWhatsapp = contact.whatsapp_numbers?.[0] || "";
  const mobileNumber = rawPhone || rawWhatsapp || "";
  const firstPhone = formatSellerPhone(mobileNumber || "Not found");
  const firstPhoneCopy = formatSellerPhone(mobileNumber);
  sellerInsightsList.appendChild(createSellerItem({
    icon: ICONS.phone, iconTone: "safe", label: "Mobile",
    value: firstPhone, copyValue: firstPhoneCopy,
  }));

  const firstWhatsapp = formatPhoneWithFallback(contact.whatsapp_numbers?.[0] || "", "");
  if (firstWhatsapp && firstWhatsapp !== "Not found") {
    sellerInsightsList.appendChild(createSellerItem({
      icon: ICONS.whatsapp, iconTone: "whatsapp", label: "WhatsApp",
      value: firstWhatsapp, copyValue: firstWhatsapp,
    }));
  }

  const firstEmail = contact.emails?.[0] || "Not found";
  const firstEmailEval = contact.email_evaluations?.[0];
  sellerInsightsList.appendChild(createSellerItem({
    icon: ICONS.email, iconTone: "safe", label: "Mail",
    value: firstEmail,
    badge: firstEmailEval ? { tone: firstEmailEval.tone === "safe" ? "safe" : "warning", text: firstEmailEval.label } : null,
    copyValue: contact.emails?.[0] || "",
  }));

  sellerInsightsList.appendChild(createSellerItem({
    icon: ICONS.policy, label: "Return & Exchange Policy",
    valueHtml: policySummaries.return_policy
      ? highlightPolicySummary(policySummaries.return_policy)
      : escapeHtml(contact.return_policy_url
        ? "Policy detected, but details couldn't be summarised."
        : "Not found"),
    allowLink: false,
  }));

  sellerInsightsList.appendChild(createSellerItem({
    icon: ICONS.policy, label: "Refund Policy",
    valueHtml: policySummaries.refund_policy
      ? highlightPolicySummary(policySummaries.refund_policy)
      : escapeHtml(contact.refund_policy_url
        ? "Policy detected, but details couldn't be summarised."
        : "Not found"),
    allowLink: false,
  }));

  sellerInsightsList.appendChild(createSellerItem({
    icon: ICONS.policy, label: "Privacy Policy",
    value: contact.privacy_policy_url ? "Open policy page" : "Not found",
    linkUrl: contact.privacy_policy_url || "",
  }));

  sellerInsightsList.appendChild(createSellerItem({
    icon: ICONS.policy, label: "Terms & Conditions",
    value: contact.terms_conditions_url ? "Open policy page" : "Not found",
    linkUrl: contact.terms_conditions_url || "",
  }));

  const registeredTo = meta.organization || meta.registrant_name || "Unknown";
  const location = meta.country ? ` (${meta.country})` : "";
  sellerInsightsList.appendChild(createSellerItem({
    icon: ICONS.whois, label: "Domain Registered To",
    value: `${registeredTo}${location}`,
  }));

  // Stagger seller items
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
  } else if (kind === "external" && payload) {
    chrome.tabs.create({ url: payload });
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

  renderSellerLoading();
  try {
    const response = await postJsonCached("/seller-insights", { url: state.lastScannedUrl }, DETAIL_CACHE_TTL_MS);
    if (response.data.analysis) {
      state.lastAnalysis = response.data.analysis;
      const threat = typeof response.data.analysis.threat_score === "number"
        ? response.data.analysis.threat_score : 0.5;
      animateRing(threat);
      setVerdict(response.data.analysis.verdict ?? response.data.analysis.level, threat);
      renderIndicators(state.lastScannedUrl, response.data.analysis, threat);
      renderChecklist(response.data.analysis.fired_rules || []);
      state.pendingExplanation = response.data.analysis.explanation || "";
      state.aiSummaryRevealed = false;
      if (state.pendingExplanation) threatExpl.classList.remove("hidden");
    }
    renderSellerInsights(response.data);
    const contact = (response.data.analysis || state.lastAnalysis)?.contact_signals || {};
    showSellerTransparencyBadge(contact);
    state.sellerInsightsLoadedFor = state.lastScannedUrl;
  } catch (err) {
    sellerInsightsList.innerHTML = `<div class="seller-item">
      <div class="seller-icon">${ICONS.policy}</div>
      <div class="seller-main">
        <div class="seller-label">Status</div>
        <div class="seller-value">${escapeHtml(err.message)}</div>
      </div></div>`;
  }
}

/* ── AI Summary toggle with typing animation ── */
function collapseAiSummary() {
  if (aiSummaryBtn) {
    aiSummaryBtn.classList.remove("open");
    aiSummaryBtn.setAttribute("aria-expanded", "false");
  }
  if (aiSummaryPanel) {
    aiSummaryPanel.classList.remove("revealed");
    aiSummaryPanel.classList.add("hidden");
  }
  clearInterval(aiTypingTimer);
  aiTypingTimer = null;
}

function typeText(element, text, speed = 12) {
  element.textContent = "";
  let i = 0;
  clearInterval(aiTypingTimer);
  aiTypingTimer = setInterval(() => {
    if (i < text.length) {
      element.textContent += text.charAt(i);
      i++;
    } else {
      clearInterval(aiTypingTimer);
      aiTypingTimer = null;
    }
  }, speed);
}

function toggleAiSummary() {
  if (!state.pendingExplanation) return;
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

  if (!state.aiSummaryRevealed) {
    typeText(explanationText, state.pendingExplanation, 12);
    state.aiSummaryRevealed = true;
  }
}

async function hydrateCurrentTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    state.currentTabUrl = tab?.url || "";
    if (state.currentTabUrl
      && !/^chrome:|^about:|^edge:|^chrome-extension:/i.test(state.currentTabUrl)
      && !urlDisplay.value.trim()) {
      urlDisplay.value = presentUrl(state.currentTabUrl);
    }
  } catch { state.currentTabUrl = ""; }
}

function restoreRecentScanForCurrentTab() {
  if (!state.currentTabUrl
    || /^(chrome|about|edge|chrome-extension):/i.test(state.currentTabUrl)) return;

  const scanUrl = urlForScan(state.currentTabUrl);
  if (!scanUrl) return;

  const cachedEntry = getCachedResponse("/predict", { url: scanUrl });
  if (!cachedEntry?.data) return;

  urlDisplay.value = presentUrl(state.currentTabUrl);
  applyAnalysis(cachedEntry.data, cachedEntry.data.url || scanUrl, {
    fromCache: true,
    savedAt: cachedEntry.savedAt,
  });
}

/* ── Bootstrap ── */
document.addEventListener("DOMContentLoaded", async () => {
  loadThemePreference();
  setIdle();
  await hydrateCurrentTab();
  restoreRecentScanForCurrentTab();

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
        navigator.clipboard.writeText(email).catch(() => {});
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
