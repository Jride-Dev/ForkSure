const results = document.querySelector("#results");
const tabs = document.querySelectorAll(".tab");

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((item) => {
      const active = item === tab;
      item.classList.toggle("is-active", active);
      item.setAttribute("aria-selected", String(active));
      document.querySelector(`#${item.dataset.panel}`).classList.toggle("is-hidden", !active);
    });
  });
});

document.querySelector("#compare-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = {
    source_repo: String(form.get("source_repo") || "").trim(),
    candidate_repo: String(form.get("candidate_repo") || "").trim(),
    include_similarity: form.has("include_similarity"),
    include_security: form.has("include_security"),
  };
  await runRequest(event.currentTarget, "/api/compare", payload, renderComparison, "Reviewing repositories");
});

document.querySelector("#matches-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = { repository: String(form.get("repository") || "").trim() };
  await runRequest(event.currentTarget, "/api/matches", payload, renderMatches, "Searching GitHub");
});

async function runRequest(form, endpoint, payload, render, label) {
  const button = form.querySelector("button[type='submit']");
  button.disabled = true;
  showLoading(label);
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "ForkSure could not complete the request.");
    render(data);
  } catch (error) {
    showError(error instanceof Error ? error.message : "ForkSure could not complete the request.");
  } finally {
    button.disabled = false;
  }
}

function renderComparison(data) {
  clearResults();
  const heading = element("div", "result-heading");
  const titleBlock = document.createElement("div");
  titleBlock.append(element("h2", "", `${text(data.source?.full_name)} vs ${text(data.candidate?.full_name)}`));
  titleBlock.append(element("p", "", "Repository evidence and risk signals"));
  heading.append(titleBlock, riskBadge(data.overall_risk));
  results.append(heading);

  const grid = element("div", "risk-grid");
  const labels = {
    name: "Name / imposter",
    readme: "README attribution",
    license: "License",
    similarity: "Code similarity",
    security: "Security",
  };
  Object.entries(labels).forEach(([key, label]) => {
    const signal = data.risk_breakdown?.[key] || {};
    const card = element("article", "signal-card");
    card.append(element("h3", "", label), riskBadge(signal.risk_level), element("p", "", text(signal.summary)));
    grid.append(card);
  });
  results.append(grid);

  const repos = element("div", "repo-grid");
  repos.append(repoCard("Source", data.source), repoCard("Candidate", data.candidate));
  results.append(repos);
}

function renderMatches(data) {
  clearResults();
  const heading = element("div", "result-heading");
  const titleBlock = document.createElement("div");
  titleBlock.append(element("h2", "", `Close matches for ${text(data.target)}`));
  titleBlock.append(element("p", "", `${Number(data.candidate_count || 0)} candidates found for manual review`));
  heading.append(titleBlock);
  results.append(heading);

  const candidates = Array.isArray(data.candidates) ? data.candidates : [];
  if (!candidates.length) {
    const empty = element("div", "empty-state");
    empty.append(element("h2", "", "No close matches found"), element("p", "", "GitHub returned no similarity candidates."));
    results.append(empty);
    return;
  }

  const list = element("div", "candidate-list");
  candidates.forEach((candidate) => list.append(candidateCard(candidate)));
  results.append(list);
}

function repoCard(label, repo = {}) {
  const card = element("article", "repo-card");
  card.append(element("p", "eyebrow", label));
  const heading = document.createElement("h3");
  heading.append(repoLink(repo.full_name, repo.html_url));
  card.append(heading);
  if (repo.description && repo.description !== "-") card.append(element("p", "description", repo.description));
  const metadata = element("div", "metadata");
  metadata.append(
    meta("Stars", repo.stargazers_count ?? 0),
    meta("Fork", repo.fork ? "Yes" : "No"),
    meta("Default branch", repo.default_branch || "-"),
    meta("License", repo.license_label || "Unknown"),
    meta("Created", repo.created_at || "-"),
    meta("Last pushed", repo.pushed_at || "-"),
  );
  card.append(metadata);
  return card;
}

function candidateCard(candidate) {
  const card = element("article", "candidate-card");
  const topline = element("div", "candidate-topline");
  const heading = document.createElement("h3");
  heading.append(repoLink(candidate.full_name, candidate.html_url));
  const badges = element("div", "candidate-badges");
  badges.append(riskBadge(candidate.risk_level));
  badges.append(element("span", "badge class-badge", text(candidate.classification || "unknown")));
  badges.append(element("span", "badge class-badge", `Score ${Number(candidate.score || 0)}`));
  topline.append(heading, badges);
  card.append(topline);
  if (candidate.description) card.append(element("p", "description", candidate.description));
  const metadata = element("div", "metadata");
  metadata.append(
    meta("Stars", candidate.stargazers_count ?? 0),
    meta("Fork", candidate.fork ? "Yes" : "No"),
    meta("License", candidate.license_name || candidate.license_key || "Unknown"),
    meta("README", candidate.readme_status || "Unknown"),
  );
  card.append(metadata);
  const reasons = Array.isArray(candidate.reasons) ? candidate.reasons : [];
  if (reasons.length) {
    const list = element("ul", "reason-list");
    reasons.forEach((reason) => list.append(element("li", "", reason)));
    card.append(list);
  }
  return card;
}

function riskBadge(risk) {
  const value = text(risk || "INFO");
  const css = value.toLowerCase().replaceAll(" ", "-").replaceAll("_", "-");
  return element("span", `badge risk-${css}`, value.toUpperCase());
}

function repoLink(name, url) {
  const link = document.createElement("a");
  link.textContent = text(name || "Unknown repository");
  const safeUrl = githubUrl(url);
  if (safeUrl) {
    link.href = safeUrl;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
  }
  return link;
}

function githubUrl(value) {
  try {
    const url = new URL(String(value || ""));
    return url.protocol === "https:" && url.hostname === "github.com" ? url.href : "";
  } catch {
    return "";
  }
}

function meta(label, value) {
  const item = element("div", "meta-item");
  item.append(element("span", "", label), element("strong", "", text(value)));
  return item;
}

function showLoading(label) {
  clearResults();
  const loading = element("div", "loading");
  loading.append(element("span", "spinner"), element("span", "", `${label}...`));
  results.append(loading);
}

function showError(message) {
  clearResults();
  const error = element("div", "error-state");
  error.append(element("h2", "", "Review could not be completed"), element("p", "", message));
  results.append(error);
}

function clearResults() {
  results.replaceChildren();
}

function element(tag, className = "", content = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content !== "") node.textContent = text(content);
  return node;
}

function text(value) {
  return value === null || value === undefined || value === "" ? "-" : String(value);
}
