import { clearNotice, showNotice } from "./api.js";
import { initDashboard, loadScans } from "./dashboard.js";
import { loadTools } from "./tools.js";
import { loadScope } from "./config.js";

const titles = {
  dashboard: "Dashboard",
  "new-scan": "New scan",
  tools: "Tools",
  config: "Config",
};

function showView(name) {
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("active", view.id === `view-${name}`);
  });
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === name && button.classList.contains("nav-link"));
  });
  document.querySelector("#page-title").textContent = titles[name] || titles.dashboard;
  clearNotice();
  if (name === "dashboard") loadScans().catch((error) => showNotice(error.message));
  if (name === "tools") loadTools().catch((error) => showNotice(error.message));
  if (name === "config") loadScope().catch((error) => showNotice(error.message));
}

document.querySelectorAll("[data-view]").forEach((button) => {
  button.addEventListener("click", (event) => {
    event.preventDefault();
    showView(button.dataset.view);
  });
});

document.querySelector("#refresh-button").addEventListener("click", () => {
  const active = document.querySelector(".view.active");
  const name = active?.id.replace("view-", "") || "dashboard";
  showView(name);
});

document.querySelector("#tools-refresh").addEventListener("click", () => {
  loadTools().catch((error) => showNotice(error.message));
});

initDashboard();
showView("dashboard");
