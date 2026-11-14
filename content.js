// Goldphish content script: intercepts link clicks on Gmail / WhatsApp Web.
// Only the clicked link's URL is sent for analysis. No message text or contacts are read.

function unwrapGoogleRedirect(href) {
  // Gmail often wraps links as https://www.google.com/url?q=<real-url>
  try {
    const u = new URL(href);
    if (u.hostname.endsWith("google.com") && u.pathname === "/url") {
      const real = u.searchParams.get("q") || u.searchParams.get("url");
      if (real) return real;
    }
  } catch (_) {}
  return href;
}

function getCheckableUrl(anchor) {
  const raw = anchor.href;
  if (!raw) return null;
  const href = unwrapGoogleRedirect(raw);
  let u;
  try {
    u = new URL(href);
  } catch (_) {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null; // skip mailto:, tel:, javascript:
  // Ignore the app's own internal links
  if (u.hostname === location.hostname) return null;
  return u.href;
}

function handleClick(event) {
  // Left click, or middle click (auxclick) only
  if (event.type === "click" && event.button !== 0) return;
  const anchor = event.target.closest && event.target.closest("a[href]");
  if (!anchor) return;

  const url = getCheckableUrl(anchor);
  if (!url) return;

  // Stop the navigation until the URL has been assessed.
  event.preventDefault();
  event.stopImmediatePropagation();

  chrome.runtime.sendMessage({ type: "CHECK_URL", url });
}

// Capture phase on document: also covers links added later (no per-link listeners needed).
document.addEventListener("click", handleClick, true);
document.addEventListener("auxclick", handleClick, true);
