const USE_LOCAL_BACKEND = false;
const API_BASE = USE_LOCAL_BACKEND
    ? "http://127.0.0.1:5000"
    : "https://threatlens-api.vercel.app";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

    // ✅ Handle ANALYZE_DATA
    if (message.type === "ANALYZE_DATA") {
        analyzeWithAPI(message.data)
            .then(result => sendResponse(result))
            .catch(err => sendResponse({ error: err.message }));
        return true;
    }

    // ✅ Handle SCAN_URL (real-time detection)
    if (message.type === "SCAN_URL") {
        // Strip URL to origin only (same as popup) to avoid ML path-bias
        let scanUrl = message.url;
        try { scanUrl = new URL(message.url).origin; } catch { }

        chrome.storage.local.get("trustSignals", (result) => {
            fetch(`${API_BASE}/predict`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    url: scanUrl,
                    signals: result.trustSignals || {}
                })
            })
                .then(res => res.json())
                .catch(err => console.error("API ERROR:", err));
        });
        return true; // ← Keep message channel open for async response
    }

    // ✅ Handle TRUST SIGNALS
    if (message.type === "TRUST_SIGNALS") {
        chrome.storage.local.set({ trustSignals: message.data });
    }
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
        const allFlags = [...(data.flags || []), ...pageFlags];

        return {
            score: data.score,
            level: data.level,
            levelClass: data.level_class,
            flags: allFlags,
            positives: data.positives || [],
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
