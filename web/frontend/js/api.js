const API_BASE = "";

export async function apiGet(path) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { Accept: "application/json" },
    credentials: "same-origin",
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${response.status} ${response.statusText}${body ? `: ${body}` : ""}`);
  }
  return response;
}

export async function getJson(path) {
  return (await apiGet(path)).json();
}

export function websocketUrl(path) {
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${window.location.host}${path}`;
}

export function showNotice(message) {
  const notice = document.querySelector("#notice");
  notice.textContent = message;
  notice.classList.remove("hidden");
}

export function clearNotice() {
  const notice = document.querySelector("#notice");
  notice.textContent = "";
  notice.classList.add("hidden");
}

export function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}
