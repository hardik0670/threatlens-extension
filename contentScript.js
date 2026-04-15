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
function triggerScan() {
    if (scanTimeout) clearTimeout(scanTimeout);
    scanTimeout = setTimeout(() => {
        const url = window.location.href;
        // Skip internal/extension pages
        if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) return;

        sendRuntimeMessage({
            type: "SCAN_URL",
            url: url
        });

        // Collect trust signals dynamically
        const links = Array.from(document.querySelectorAll("a"))
            .map(a => a.innerText.toLowerCase());

        sendRuntimeMessage({
            type: "TRUST_SIGNALS",
            data: {
                hasContact: links.some(text => text.includes("contact")),
                hasPrivacy: links.some(text => text.includes("privacy")),
                hasRefund: links.some(text => text.includes("refund") || text.includes("return")),
            }
        });
    }, 1500); // debounce 1.5 seconds
}

// Automatically sends scan request + trust signals when page loads
window.addEventListener("load", triggerScan);

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
