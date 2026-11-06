const API_BASE = "https://threatlens-api.vercel.app";

const SIGNAL_TTL_MS = 5 * 60 * 1000;

function signalKey(tabId) { return `page-signals-v3:${tabId}`; }

async function saveSignals(sender, signals) {
    if (sender.tab?.id == null || sender.frameId !== 0) return;
    await chrome.storage.session.set({
        [signalKey(sender.tab.id)]: { url: sender.url, signals: { ...signals, sourceUrl: new URL(sender.url).origin + new URL(sender.url).pathname }, savedAt: Date.now() }
    });
}

async function readSignals(tabId, url) {
    const key = signalKey(tabId);
    const entry = (await chrome.storage.session.get(key))[key];
    if (!entry || Date.now() - entry.savedAt > SIGNAL_TTL_MS) return {};
    try {
        const page = new URL(entry.url);
        const target = new URL(url);
        page.hash = "";
        target.hash = "";
        if (page.origin !== target.origin) return {};
        if (target.pathname !== "/" || target.search) {
            if (page.href !== target.href) return {};
        }
        return entry.signals;
    } catch { return {}; }
}

chrome.tabs.onRemoved.addListener(tabId => {
    chrome.storage.session.remove([signalKey(tabId), `page-scan-v3:${tabId}`]);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const handle = async () => {
        if (message.type === "GET_TRUST_SIGNALS") {
            if (sender.tab) return {};
            const tab = await chrome.tabs.get(message.tabId);
            if (new URL(tab.url).origin !== new URL(message.url).origin) return {};
            try {
                const fresh = await chrome.tabs.sendMessage(message.tabId, { type: "COLLECT_SELLER_SIGNALS" }, { frameId: 0 });
                if (fresh && !fresh.error) await saveSignals({ tab, frameId: 0, url: tab.url }, fresh);
            } catch { /* Content scripts may be unavailable on restricted tabs. */ }
            return readSignals(message.tabId, message.url);
        }
        if (message.type === "TRUST_SIGNALS") {
            await saveSignals(sender, message.data);
            return { ok: true };
        }
        if (message.type === "SCAN_URL") {
            if (!sender.tab || sender.frameId !== 0) return { error: "Missing page context" };
            // Capture signals with the scan so storage writes cannot race the request.
            if (message.signals) await saveSignals(sender, message.signals);
            const scanUrl = new URL(sender.url).origin;
            const signals = await readSignals(sender.tab.id, scanUrl);
            const response = await fetch(`${API_BASE}/predict`, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: scanUrl, signals }),
                signal: AbortSignal.timeout(15000)
            });
            if (!response.ok) throw new Error(`API returned ${response.status}`);
            const analysis = await response.json();
            await chrome.storage.session.set({ [`page-scan-v3:${sender.tab.id}`]: { url: scanUrl, analysis, savedAt: Date.now() } });
            return analysis;
        }
        if (message.type === "GET_RECENT_SCAN") {
            if (sender.tab) return null;
            const key = `page-scan-v3:${message.tabId}`;
            const entry = (await chrome.storage.session.get(key))[key];
            return entry && entry.url === message.url && Date.now() - entry.savedAt < SIGNAL_TTL_MS ? entry : null;
        }
        if (message.type === "ANALYZE_DATA") return analyzeWithAPI(message.data);
        return { error: "Unknown message" };
    };
    handle().then(sendResponse).catch(() => sendResponse({ error: "Page analysis unavailable" }));
    return true;
});

function extractBaseUrl(fullUrl) {
    try {
        const parsed = new URL(fullUrl);
        // Keep scheme + hostname only (strip path, query, fragment)
        return `${parsed.protocol}//${parsed.hostname}`;
    } catch {
        return fullUrl;
    }
}


// ─── Primary: ML API ──────────────────────────────────────────────────────────

async function analyzeWithAPI(pageData) {
    // Use base URL only for ML analysis
    const baseUrl = extractBaseUrl(pageData.url);

    try {
        const response = await fetch(`${API_BASE}/predict`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: baseUrl }),
            signal: AbortSignal.timeout(8000)
        });

        if (!response.ok) throw new Error(`API returned ${response.status}`);

        const data = await response.json();

        // Merge URL-based ML flags with live DOM signals from contentScript
        const pageFlags = buildPageFlags(pageData);
        const allFlags = [...(data.fired_rules || []).filter(rule => rule.adjustment > 0).map(rule => ({ label: rule.rule, detail: rule.reason, severity: rule.adjustment >= 0.2 ? "high" : "medium" })), ...pageFlags];

        return {
            score: Math.round((1 - data.threat_score) * 100),
            level: data.verdict,
            levelClass: data.threat_score > 0.5 ? "high" : data.threat_score > 0.3 ? "medium" : "low",
            flags: allFlags,
            positives: (data.fired_rules || []).filter(rule => rule.adjustment < 0).map(rule => rule.reason),
            domain: data.domain || pageData.domain,
            domain_age_str: data.domain_age_str || null,
            domain_age_days: data.domain_age_days ?? -1,  // ← needed for color coding
            explanation: data.explanation || null,  // ← Gemini text
            source: "ml"
        };

    } catch (err) {
        console.warn("[ThreatLens] API unavailable, using fallback:", err.message);
        return analyzeWithRules(pageData);
    }
}


// ─── Page-level DOM signals ───────────────────────────────────────────────────

function buildPageFlags(data) {
    const flags = [];

    if (data.keywordMatches >= 3) {
        flags.push({ label: "Phishing language on page", detail: `${data.keywordMatches} suspicious phrases in page content`, severity: "high" });
    } else if (data.keywordMatches >= 1) {
        flags.push({ label: "Suspicious language on page", detail: `${data.keywordMatches} suspicious phrase(s) found`, severity: "medium" });
    }
    if (data.iframes > 8) {
        flags.push({ label: "Excessive iframes", detail: `${data.iframes} iframes detected`, severity: "high" });
    } else if (data.iframes > 3) {
        flags.push({ label: "Many iframes", detail: `${data.iframes} iframes on this page`, severity: "medium" });
    }
    if (data.passwordFields > 0 && data.forms === 0) {
        flags.push({ label: "Password field outside a form", detail: "Common in credential-harvesting pages", severity: "high" });
    }
    if (data.metaRefresh) {
        flags.push({ label: "Auto-redirect on page", detail: "Page redirects automatically", severity: "medium" });
    }
    if (data.externalScripts > 30) {
        flags.push({ label: "Many external scripts", detail: `${data.externalScripts} scripts loaded from other domains`, severity: "medium" });
    }

    return flags;
}


// ─── Fallback: Rule-based scorer (when Flask is offline) ─────────────────────

function analyzeWithRules(data) {
    let score = 100;
    const flags = [];
    const positives = [];

    if (!data.isHttps) {
        score -= 25;
        flags.push({ label: "No HTTPS", detail: "Connection is unencrypted", severity: "high" });
    } else {
        positives.push("HTTPS encryption active");
    }
    if (data.passwordFields > 0 && data.forms === 0) {
        score -= 20;
        flags.push({ label: "Suspicious password field", detail: "Password input outside a form", severity: "high" });
    }
    if (data.iframes > 8) {
        score -= 20;
        flags.push({ label: "Excessive iframes", detail: `${data.iframes} iframes detected`, severity: "high" });
    } else if (data.iframes > 3) {
        score -= 10;
        flags.push({ label: "Many iframes", detail: `${data.iframes} iframes detected`, severity: "medium" });
    }
    if (data.keywordMatches >= 3) {
        score -= 25;
        flags.push({ label: "Phishing language detected", detail: `${data.keywordMatches} suspicious phrases`, severity: "high" });
    } else if (data.keywordMatches >= 1) {
        score -= 12;
        flags.push({ label: "Suspicious language", detail: `${data.keywordMatches} phrase(s) found`, severity: "medium" });
    }
    if (data.metaRefresh) {
        score -= 15;
        flags.push({ label: "Auto-redirect detected", detail: "Page redirects via meta tag", severity: "medium" });
    }

    const domain = data.domain || "";
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
        score -= 30;
        flags.push({ label: "IP address as domain", detail: "Legitimate sites use domain names", severity: "high" });
    }

    if (data.forms === 0 && data.passwordFields === 0) positives.push("No suspicious form structures");
    if (data.iframes === 0) positives.push("No iframes detected");
    if (data.keywordMatches === 0) positives.push("No phishing language detected");

    score = Math.max(0, Math.min(100, score));

    let level, levelClass;
    if (score >= 75) { level = "Low Risk"; levelClass = "low"; }
    else if (score >= 45) { level = "Medium Risk"; levelClass = "medium"; }
    else { level = "High Risk"; levelClass = "high"; }

    return {
        score, level, levelClass, flags, positives,
        domain, domain_age_str: null, explanation: null, source: "fallback"
    };
}
