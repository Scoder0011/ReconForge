import { element, getJson } from "./api.js";

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
