import { deleteRequest, element, getJson, showNotice, websocketUrl } from "./api.js";
import { selectScan } from "./results.js";

let activeSocket = null;

function formatDate(value) {
  if (!value) return "time unavailable";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

function renderScan(scan) {
  const card = element("article", "scan-card");
  const details = element("div");
  details.append(element("h3", "", scan.target));
  details.append(element("div", "scan-meta", `${formatDate(scan.started_at)} · ${scan.id}`));
  const actions = element("div", "scan-actions");
  actions.append(element("span", `status-pill ${scan.status}`, scan.status));
  const openButton = element("button", "button secondary", "Browse results");
  openButton.type = "button";
  openButton.addEventListener("click", () => selectScan(scan));
  actions.append(openButton);
  const deleteButton = element("button", "button danger", "Delete history");
  deleteButton.type = "button";
  deleteButton.setAttribute("aria-label", `Delete ${scan.target} from scan history`);
  deleteButton.addEventListener("click", async () => {
    const confirmed = window.confirm(
      `Remove the ${scan.target} scan from dashboard history?\n\nThis does not delete its output files.`
    );
    if (!confirmed) return;
    deleteButton.disabled = true;
    try {
      await deleteRequest(`/api/scans/${encodeURIComponent(scan.id)}`);
      if (activeSocket && scan.status === "running") {
        activeSocket.close();
        activeSocket = null;
      }
      await loadScans();
      showNotice("Scan removed from history. Its output files were retained.");
    } catch (error) {
      deleteButton.disabled = false;
      showNotice(`Could not delete scan history: ${error.message}`);
    }
  });
  actions.append(deleteButton);
  if (scan.status === "running") {
    const progressButton = element("button", "button secondary", "Live progress");
    progressButton.type = "button";
    progressButton.addEventListener("click", () => watchScan(scan));
    actions.append(progressButton);
  }
  card.append(details, actions);
  return card;
}

export async function loadScans() {
  const root = document.querySelector("#scan-list");
  root.replaceChildren(element("div", "empty-state", "Loading scan history…"));
  const scans = await getJson("/api/scans");
  root.replaceChildren();
  if (!scans.length) {
    root.append(element("div", "empty-state", "No recorded scans yet. Start one from the CLI to populate history."));
    return;
  }
  scans.forEach((scan) => root.append(renderScan(scan)));
}

function watchScan(scan) {
  if (activeSocket) activeSocket.close();
  document.querySelector("#progress-panel").classList.remove("hidden");
  document.querySelector("#progress-title").textContent = `${scan.target} · ${scan.id}`;
  document.querySelector("#progress-list").replaceChildren(element("div", "empty-state", "Connecting to event stream…"));
  const state = document.querySelector("#ws-state");
  state.textContent = "Connecting";
  activeSocket = new WebSocket(websocketUrl(`/ws/scans/${encodeURIComponent(scan.id)}`));
  activeSocket.addEventListener("open", () => { state.textContent = "Connected"; });
  activeSocket.addEventListener("message", (message) => {
    try {
      renderEvent(JSON.parse(message.data));
    } catch {
      showNotice("Received an invalid progress event.");
    }
  });
  activeSocket.addEventListener("close", () => { state.textContent = "Disconnected"; });
  activeSocket.addEventListener("error", () => {
    state.textContent = "Unavailable";
    showNotice("Live progress is unavailable for this scan. CLI-started scans may not publish events to this server process.");
  });
}

function renderEvent(event) {
  const root = document.querySelector("#progress-list");
  if (root.querySelector(".empty-state")) root.replaceChildren();
  const row = element("div", `event-row ${event.status || ""}`);
  const label = element("strong", "", `${event.stage || "stage"} · ${event.status || "event"}`);
  const detail = event.reason || (event.counts ? Object.entries(event.counts).map(([key, value]) => `${key}: ${value}`).join(" · ") : "");
  row.append(label, element("span", event.reason ? "event-reason" : "event-counts", detail));
  root.append(row);
}

export function initDashboard() {
  document.querySelector("#scan-form").addEventListener("submit", (event) => {
    event.preventDefault();
    showNotice("Scan launch is disabled because this API is read-only. Use the CLI to run a scan.");
  });
}
