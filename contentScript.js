function collectPageData() {
    const url = window.location.href;
    const hostname = window.location.hostname;

    // External links — count how many point outside this domain
    const allLinks = Array.from(document.querySelectorAll("a[href]"));
    const externalLinks = allLinks.filter(a => {
        try { return new URL(a.href).hostname !== hostname; } catch { return false; }
    }).length;

    // Hidden form fields (common in phishing)
    const hiddenInputs = document.querySelectorAll("input[type='hidden']").length;

    // External scripts (scripts loaded from other domains)
    const allScripts = Array.from(document.querySelectorAll("script[src]"));
    const externalScripts = allScripts.filter(s => {
        try { return new URL(s.src).hostname !== hostname; } catch { return false; }
    }).length;

    // Suspicious keywords in visible text
    const pageText = (document.body.innerText || "").toLowerCase().substring(0, 3000);
    const suspiciousKeywords = [
        "verify your account", "confirm your identity", "click here to claim",
        "your account has been suspended", "unusual activity", "enter your password",
        "limited time offer", "you have won", "congratulations", "wire transfer",
        "gift card", "bitcoin", "urgent action required"
    ];
    const keywordMatches = suspiciousKeywords.filter(kw => pageText.includes(kw)).length;

    // Redirect meta tags
    const metaRefresh = document.querySelector("meta[http-equiv='refresh']") ? 1 : 0;

    const data = {
        url: url,
        domain: hostname,
        isHttps: url.startsWith("https"),
        forms: document.querySelectorAll("form").length,
        iframes: document.querySelectorAll("iframe").length,
        totalScripts: document.querySelectorAll("script").length,
        externalScripts: externalScripts,
        passwordFields: document.querySelectorAll("input[type='password']").length,
        hiddenInputs: hiddenInputs,
        externalLinks: externalLinks,
        totalLinks: allLinks.length,
        keywordMatches: keywordMatches,
        metaRefresh: metaRefresh,
        title: document.title || ""
    };

    return data;
}

function isExtensionContextAvailable() {
    try {
        return typeof chrome !== "undefined" && !!chrome.runtime?.id;
    } catch {
        return false;
    }
}

function sendRuntimeMessage(message) {
    if (!isExtensionContextAvailable()) return;
    try {
        chrome.runtime.sendMessage(message, () => {
            void chrome.runtime?.lastError;
        });
    } catch (error) {
        const text = String(error?.message || error || "");
        if (!text.includes("Extension context invalidated")) {
            console.warn("[ThreatLens] runtime message failed:", error);
        }
    }
}

if (isExtensionContextAvailable()) {
    try {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            if (request.type === "SCAN_PAGE") {
                const pageData = collectPageData();
                sendResponse(pageData);
            }
            if (request.type === "COLLECT_SELLER_SIGNALS") sendResponse(collectSellerSignals());
            return true; // keep message channel open for async
        });
    } catch (error) {
        const text = String(error?.message || error || "");
        if (!text.includes("Extension context invalidated")) {
            console.warn("[ThreatLens] listener setup failed:", error);
        }
    }
}


let scanTimeout = null;
function collectSellerSignals() {
    const source = new URL(location.href);
    source.search = "";
    source.hash = "";
    const result = { sourceUrl: source.href, pageTitle: document.title.slice(0, 300),
        contactBlocks: [], policyBlocks: [], domLinks: [] };
    // Public merchant evidence only. Never collect entered values or account pages.
    if (/(?:^|\/)(?:account|checkout|orders|login|admin)(?:\/|$)/i.test(source.pathname)) return result;
    const visible = el => !el.closest("form, input, textarea, select, [contenteditable], [hidden], [aria-hidden='true']") && el.getClientRects().length > 0;
    const compact = el => (el.innerText || "").replace(/\s+/g, " ").trim();
    const anchors = [...document.querySelectorAll("a[href]")].filter(visible);
    result.domLinks = anchors.filter(a => /contact|privacy|terms|refund|return|exchange|shipping|delivery|cancellation|support/i.test(a.href + " " + compact(a)))
        .slice(0, 80).map(a => ({ href: a.href.slice(0, 1000), text: compact(a).slice(0, 150) }));
    const seen = new Set();
    for (const el of document.querySelectorAll("p, li, address, a, span")) {
        if (!visible(el) || el.closest("nav") || el.querySelector("p, li, address")) continue;
        const text = compact(el);
        const href = el.tagName === "A" ? el.href : undefined;
        if (!text || text.length > 700 || seen.has(text)) continue;
        if (!(/(?:phone|telephone|mobile|call|whats\s*app|support|exchange|contact|india|tamil nadu|maharashtra)/i.test(text) && /\d/.test(text))
            && !/@|\+\d/.test(text) && !/^(?:tel:|mailto:)|wa\.me\//i.test(href || "")) continue;
        seen.add(text);
        result.contactBlocks.push({ text, ...(href ? { href: href.slice(0, 1000) } : {}) });
        if (result.contactBlocks.length >= 60) { result.evidenceTruncated = true; break; }
    }
    if (/policy|policies|refund|return|exchange|shipping|delivery|cancellation|privacy|terms/i.test(source.pathname + " " + document.title)) {
        const main = document.querySelector(".shopify-policy__body, main, [role='main'], article, #MainContent");
        let total = 0;
        if (main) for (const el of main.querySelectorAll("h1,h2,h3,h4,h5,h6,p,li,tr")) {
            if (!visible(el) || el.closest("nav, footer, header, aside") || (el.tagName === "P" && el.closest("li, tr"))) continue;
            const text = compact(el);
            if (!text || text.length > 1500) continue;
            total += text.length;
            if (total > 40000) { result.evidenceTruncated = true; break; }
            result.policyBlocks.push({ text, level: /^H[1-6]$/.test(el.tagName) ? Number(el.tagName[1]) : 0 });
            if (result.policyBlocks.length >= 120) { result.evidenceTruncated = true; break; }
        }
    }
    return result;
}

function triggerScan() {
    if (scanTimeout) clearTimeout(scanTimeout);
    scanTimeout = setTimeout(() => {
        const url = window.location.href;
        // Skip internal/extension pages
        if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) return;

        const signals = collectSellerSignals();

        // Capture signals together with the scan
        sendRuntimeMessage({
            type: "SCAN_URL",
            url: url,
            signals
        });
    }, 1500); // debounce 1.5 seconds
}

// Automatically sends scan request + trust signals when page loads
if (document.readyState === "complete") triggerScan();
else window.addEventListener("load", triggerScan, { once: true });

// SPA Support: Watch for dynamically injected login/checkout forms
const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    for (let m of mutations) {
        if (m.addedNodes.length > 0) {
            for (let node of m.addedNodes) {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    // Check if a form or a password field was dynamically injected
                    if (node.tagName === "FORM" || node.tagName === "INPUT" || node.querySelector("form, input[type='password']")) {
                        shouldScan = true;
                        break;
                    }
                }
            }
        }
        if (shouldScan) break;
    }
    if (shouldScan) triggerScan();
});

// Start watching the document body for changes
if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
} else {
    document.addEventListener("DOMContentLoaded", () => {
        observer.observe(document.body, { childList: true, subtree: true });
    });
}


// End of content script
