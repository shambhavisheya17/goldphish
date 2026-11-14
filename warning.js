// Warning page logic. Uses textContent only (never innerHTML) so URLs cannot inject markup.
const params = new URLSearchParams(location.search);
const url = params.get("u") || "";

const LABELS = { low: "Low risk", medium: "Medium risk", high: "High risk", blocked: "Blocked: known malicious" };

chrome.runtime.sendMessage({ type: "ANALYZE", url }, (r) => {
  if (!r) return;
  const badge = document.getElementById("badge");
  badge.textContent = LABELS[r.level] || r.level;
  badge.className = "badge " + r.level;
  document.getElementById("url").textContent = r.url;

  const list = document.getElementById("reasons");
  (r.reasons.length ? r.reasons : ["No specific indicators found."]).forEach((text) => {
    const li = document.createElement("li");
    li.textContent = text;
    list.appendChild(li);
  });

  if (r.blocked) document.getElementById("go").hidden = true; // blocklist hits cannot be bypassed
});

document.getElementById("back").addEventListener("click", () => {
  chrome.tabs.getCurrent((tab) => tab && chrome.tabs.remove(tab.id));
});

document.getElementById("go").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "PROCEED", url });
});
