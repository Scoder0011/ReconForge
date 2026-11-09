import { element, getJson, putJson, showNotice } from "./api.js";

function parsePatterns(value) {
  return value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function renderList(title, values) {
  const section = element("section", "scope-block");
  section.append(element("h3", "", title));
  const list = document.createElement("ul");
  (Array.isArray(values) ? values : []).forEach((value) => list.append(element("li", "", value)));
  if (!list.childElementCount) list.append(element("li", "muted", "None configured"));
  section.append(list);
  return section;
}

export async function loadScope() {
  const root = document.querySelector("#scope-view");
  root.replaceChildren(element("div", "empty-state", "Loading scope configuration…"));
  const scope = await getJson("/api/config/scope");
  document.querySelector("#scope-in-scope").value = (scope.in_scope || []).join("\n");
  document.querySelector("#scope-out-of-scope").value = (scope.out_of_scope || []).join("\n");
  document.querySelector("#scope-allow-vuln").checked = scope.allow_vuln_scans === true;
  root.replaceChildren();
  root.append(element("div", "scope-block", `Target: ${scope.target || "not configured"}`));
  root.append(renderList("In scope", scope.in_scope));
  root.append(renderList("Out of scope", scope.out_of_scope));
  const flags = element("section", "scope-block");
  flags.append(element("h3", "", "Authorization flags"));
  flags.append(element("p", "", `Active scans: ${scope.allow_active_scans ? "enabled" : "disabled"}`));
  flags.append(element("p", "", `Vulnerability scans: ${scope.allow_vuln_scans ? "enabled" : "disabled"}`));
  root.append(flags);
}

document.querySelector("#scope-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    await putJson("/api/config/scope", {
      in_scope: parsePatterns(document.querySelector("#scope-in-scope").value),
      out_of_scope: parsePatterns(document.querySelector("#scope-out-of-scope").value),
      allow_vuln_scans: document.querySelector("#scope-allow-vuln").checked,
    });
    showNotice("Scope saved. Vulnerability-scan consent was updated; scanners remain unavailable unless implemented and explicitly enabled.");
    await loadScope();
  } catch (error) {
    showNotice(`Could not save scope: ${error.message}`);
  } finally {
    button.disabled = false;
  }
});
