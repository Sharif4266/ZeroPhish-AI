// content.js - ZeroPhish AI
// This script runs inside web pages (like Gmail/Outlook) to extract links for scanning.

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "extract_links") {
        const links = Array.from(document.querySelectorAll('a'))
            .map(a => ({ href: a.href, text: a.innerText.trim() }))
            .filter(link => link.href.startsWith('http'))
            .filter(link => !link.href.includes('google.com') && !link.href.includes('gstatic.com')); // Filter out noise

        sendResponse({ links: links });
    }
    return true;
});

// For Gmail specifically: We can detect when an email is opened
console.log("[ZeroPhish] Neural Protection Active on this page.");
