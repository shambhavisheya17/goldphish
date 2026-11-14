// Goldphish service worker: receives URLs from the content script, analyzes them,
// then either opens the link (low risk) or shows the warning page.
import { analyzeUrl, loadData } from "./analyzer.js";

// Load the data store (data/goldphish-data.json) once and reuse it.
let dataPromise = null;
function getData() {
  if (!dataPromise) dataPromise = loadData();
  return dataPromise;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // From the content script: a link was clicked
  if (msg.type === "CHECK_URL") {
    getData().then((D) => {
      const result = analyzeUrl(msg.url, D);
      const tab = sender.tab;
      const pos = tab ? { index: tab.index + 1, openerTabId: tab.id } : {};

      if (result.level === "low") {
        chrome.tabs.create({ url: result.url, ...pos });
      } else {
        const warning = chrome.runtime.getURL("warning.html") + "?u=" + encodeURIComponent(result.url);
        chrome.tabs.create({ url: warning, ...pos });
      }
    });
    return; // no response needed
  }

  // From the warning page: get the analysis for display
  if (msg.type === "ANALYZE") {
    getData().then((D) => sendResponse(analyzeUrl(msg.url, D)));
    return true; // keep the channel open until the data has loaded and we reply
  }

  // From the warning page: user chose to continue (never allowed for blocked links)
  if (msg.type === "PROCEED") {
    getData().then((D) => {
      const result = analyzeUrl(msg.url, D);
      if (!result.blocked && sender.tab) {
        chrome.tabs.update(sender.tab.id, { url: result.url });
      }
    });
  }
});
