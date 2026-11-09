import { element, getJson } from "./api.js";

export async function loadTools() {
  const root = document.querySelector("#tools-table");
  root.replaceChildren(element("div", "empty-state", "Checking registered tools…"));
  const tools = await getJson("/api/tools");
  const table = document.createElement("table");
  const head = document.createElement("thead");
  const header = document.createElement("tr");
  ["Tool", "Stage", "Status", "Resolved binary", "Install"].forEach((label) => header.append(element("th", "", label)));
  head.append(header);
  const body = document.createElement("tbody");
  tools.forEach((tool) => {
    const row = document.createElement("tr");
    row.append(
      element("td", "", tool.name),
      element("td", "", tool.stage),
      element("td", tool.installed ? "ran" : "skipped", tool.installed ? `Installed${tool.version ? ` · ${tool.version}` : ""}` : "Missing"),
      element("td", "", tool.resolved_binary || tool.path || "—"),
    );
    const action = document.createElement("td");
    const button = element("button", "button secondary", tool.installed ? "Installed" : "Install unavailable");
    button.type = "button";
    button.disabled = true;
    button.title = "Tool installation is not exposed by the read-only local API.";
    action.append(button);
    row.append(action);
    body.append(row);
  });
  table.append(head, body);
  root.replaceChildren(table);
}
