import { element, getJson, showNotice } from "./api.js";

const stages = [
  ["subdomains", "Subdomains"],
  ["dns", "DNS"],
  ["live_hosts", "Live hosts"],
  ["ports", "Ports / TLS"],
  ["screenshots", "Screenshots"],
  ["js", "JavaScript"],
  ["parameters", "Parameters"],
  ["content_discovery", "Content"],
  ["vulnerabilities", "Vulnerabilities"],
  ["cloud_secrets", "Cloud / secrets"],
  ["osint", "OSINT"],
];

let selectedScanId = null;
let currentRows = [];
let sortColumn = null;
let sortAscending = true;

function rowsFor(payload) {
  if (Array.isArray(payload)) {
    return payload.map((value) => value && typeof value === "object" ? value : { value });
  }
  if (payload && typeof payload === "object") {
    const entries = Object.entries(payload);
    if (entries.length && entries.every(([, value]) => Array.isArray(value))) {
      return entries.flatMap(([group, values]) => values.map((value) => ({ group, value })));
    }
    return [payload];
  }
  return [{ value: payload }];
}

function cellValue(value) {
  if (value === null || value === undefined) return "";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

function renderTable(rows) {
  currentRows = rows;
  const root = document.querySelector("#result-table");
  const filter = document.querySelector("#result-filter").value.trim().toLowerCase();
  const filtered = rows.filter((row) => JSON.stringify(row).toLowerCase().includes(filter));
  if (sortColumn) {
    filtered.sort((left, right) => cellValue(left[sortColumn]).localeCompare(cellValue(right[sortColumn]), undefined, { numeric: true }) * (sortAscending ? 1 : -1));
  }
  document.querySelector("#result-count").textContent = `${filtered.length} of ${rows.length} records`;
  root.replaceChildren();
  if (!filtered.length) {
    root.append(element("div", "empty-state", rows.length ? "No rows match this filter." : "No results recorded for this stage."));
    return;
  }
  const columns = [...new Set(filtered.flatMap((row) => Object.keys(row)))];
  const table = document.createElement("table");
  const head = document.createElement("thead");
  const headerRow = document.createElement("tr");
  columns.forEach((column) => {
    const th = document.createElement("th");
    const button = element("button", "", `${column}${sortColumn === column ? (sortAscending ? " ↑" : " ↓") : ""}`);
    button.type = "button";
    button.addEventListener("click", () => {
      sortAscending = sortColumn === column ? !sortAscending : true;
      sortColumn = column;
      renderTable(currentRows);
    });
    th.append(button);
    headerRow.append(th);
  });
  head.append(headerRow);
  const body = document.createElement("tbody");
  filtered.forEach((row) => {
    const tr = document.createElement("tr");
    columns.forEach((column) => tr.append(element("td", "", cellValue(row[column]))));
    body.append(tr);
  });
  table.append(head, body);
  root.append(table);
}

async function showStage(stage) {
  if (!selectedScanId) return;
  document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.stage === stage));
  const root = document.querySelector("#result-table");
  root.replaceChildren(element("div", "empty-state", "Loading results…"));
  try {
    const payload = await getJson(`/api/scans/${encodeURIComponent(selectedScanId)}/results/${stage}`);
    renderTable(rowsFor(payload.items ?? payload));
  } catch (error) {
    root.replaceChildren(element("div", "empty-state", error.message));
  }
}

export async function selectScan(scan) {
  selectedScanId = scan.id;
  document.querySelector("#selected-scan-title").textContent = `${scan.target} · ${scan.status}`;
  document.querySelector("#results-panel").classList.remove("hidden");
  document.querySelector("#report-link").href = `/api/scans/${encodeURIComponent(scan.id)}/report`;
  const tabs = document.querySelector("#result-tabs");
  tabs.replaceChildren();
  stages.forEach(([stage, label]) => {
    const button = element("button", "tab", label);
    button.type = "button";
    button.dataset.stage = stage;
    button.addEventListener("click", () => showStage(stage));
    tabs.append(button);
  });
  document.querySelector("#result-filter").value = "";
  await showStage("subdomains");
  document.querySelector("#results-panel").scrollIntoView({ behavior: "smooth", block: "start" });
}

document.querySelector("#result-filter").addEventListener("input", () => renderTable(currentRows));
document.querySelector("#export-format").addEventListener("change", (event) => {
  const format = event.target.value;
  if (!format || !selectedScanId) return;
  window.location.assign(`/api/scans/${encodeURIComponent(selectedScanId)}/export/${format}`);
  event.target.value = "";
});
