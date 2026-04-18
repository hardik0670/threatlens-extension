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

        // Collect trust signals dynamically
        const aTags = Array.from(document.querySelectorAll("a"));
        const linksAttr = aTags.map(a => a.href).filter(Boolean);
        const linksText = aTags.map(a => (a.innerText || "").toLowerCase());

        const waLinks = linksAttr.filter(href => href.includes("wa.me/") || href.includes("api.whatsapp.com/"));
        const waNumbers = waLinks.map(href => {
            let match = href.match(/(?:wa\.me\/|phone=)(\+?\d+)/);
            return match ? match[1] : null;
        }).filter(Boolean);

        const interestingKeywords = ["contact", "privacy", "term", "refund", "return", "shipping", "about", "support", "help", "store", "locator"];
        const domLinks = aTags
            .filter(a => {
                const text = (a.innerText || "").toLowerCase();
                const href = (a.href || "").toLowerCase();
                return interestingKeywords.some(kw => text.includes(kw) || href.includes(kw));
            })
            .map(a => ({ href: a.href, text: (a.innerText || "").replace(/\s+/g, " ").trim().substring(0, 100) }));

        // Extract emails directly from page text (catches non-<a> nested emails)
        const emailRegex = /([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi;
        const pageText = document.body.innerText || "";
        const rawEmails = pageText.match(emailRegex) || [];
        const validEmails = rawEmails.filter(e => e.includes('.') && e.indexOf('@') > 0).map(e => e.toLowerCase());

        // Extract high-confidence phone numbers directly from text (starts with +, or toll-free)
        const strictPhoneRegex = /(?:\+\d{1,3}[\s\-()]*(?:\d[\s\-()]*){8,14})|(?:\b(?:1800|1860|0800)[\s\-()]*(?:\d[\s\-()]*){6,10}\b)/g;
        const rawPhones = pageText.match(strictPhoneRegex) || [];
        const validPhones = rawPhones.map(p => p.trim()).filter(p => {
            const digits = p.replace(/\D/g, "");
            return digits.length >= 10 && digits.length <= 15 && new Set(digits).size > 2;
        });

        sendRuntimeMessage({
            type: "TRUST_SIGNALS",
            data: {
                hasContact: linksText.some(text => text.includes("contact")),
                hasPrivacy: linksText.some(text => text.includes("privacy")),
                hasRefund: linksText.some(text => text.includes("refund") || text.includes("return")),
                waNumbers: [...new Set(waNumbers)],
                emails: [...new Set(validEmails)],
                phones: [...new Set(validPhones)],
                domLinks: domLinks.slice(0, 50) // limit size to prevent payload bloat
            }
        });

        // Trigger scan AFTER signals are captured
        sendRuntimeMessage({
            type: "SCAN_URL",
            url: url
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
