// Injected Content Script for PhishShield AI
console.log("🛡️ PhishShield AI active on page:", window.location.href);

// Listen for messages from extension popup or background worker
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getPageInfo") {
    sendResponse({
      url: window.location.href,
      domain: window.location.hostname,
      hasPasswordInput: !!document.querySelector("input[type='password']"),
      formActions: Array.from(document.querySelectorAll("form")).map(f => f.action)
    });
  }
  return true;
});
