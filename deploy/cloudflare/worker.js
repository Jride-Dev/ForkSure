const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const RISK_ORDER = { "not scanned": -1, INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/api/health" && request.method === "GET") {
        return json({ status: "ok" });
      }
      if (url.pathname === "/api/capabilities" && request.method === "GET") {
        return json({ hosted: true, similarity: false, security: false });
      }
      if (url.pathname === "/api/compare" && request.method === "POST") {
        return json(await compareRepositories(await request.json(), env));
      }
      if (url.pathname === "/api/matches" && request.method === "POST") {
        return json(await findMatches(await request.json(), env));
      }
      if (url.pathname.startsWith("/api/")) return json({ detail: "Not found." }, 404);

      const response = await env.ASSETS.fetch(request);
      return withSecurityHeaders(response);
    } catch (error) {
      const status = Number(error?.status || 500);
      const detail = status === 500 ? "ForkSure could not complete the scan." : String(error.message || error);
      return json({ detail }, status);
    }
  },
};

async function compareRepositories(payload, env) {
  const sourceSlug = validSlug(payload.source_repo);
  const candidateSlug = validSlug(payload.candidate_repo);
  const [sourceRepo, candidateRepo, sourceLicense, candidateLicense, sourceReadme, candidateReadme] = await Promise.all([
    githubRepo(sourceSlug, env),
    githubRepo(candidateSlug, env),
    githubOptional(`/repos/${sourceSlug}/license`, env),
    githubOptional(`/repos/${candidateSlug}/license`, env),
    githubOptional(`/repos/${sourceSlug}/readme`, env),
    githubOptional(`/repos/${candidateSlug}/readme`, env),
  ]);

  const source = repoSummary(sourceRepo, sourceLicense, sourceReadme);
  const candidate = repoSummary(candidateRepo, candidateLicense, candidateReadme);
  const nameSimilarity = nameScore(sourceRepo.name, candidateRepo.name, Boolean(candidateRepo.fork));
  const licenseComparison = compareLicenses(sourceLicense, candidateLicense);
  const readmeComparison = compareReadmes(sourceSlug, sourceReadme, candidateReadme);
  const breakdown = {
    name: nameRisk(source, candidate, nameSimilarity),
    readme: readmeRisk(candidate, nameSimilarity, readmeComparison),
    license: licenseRisk(licenseComparison),
    similarity: riskItem("not scanned", "Exact-file similarity is available in the local ForkSure app."),
    security: riskItem("not scanned", "Security scanning is available in the local ForkSure app."),
  };
  breakdown.overall = overallRisk(breakdown);
  return {
    source,
    candidate,
    name_similarity: nameSimilarity,
    license_comparison: licenseComparison,
    readme_comparison: readmeComparison,
    risk_breakdown: breakdown,
    overall_risk: breakdown.overall.risk_level,
    reasons: breakdown.overall.reasons,
  };
}

async function findMatches(payload, env) {
  const input = String(payload.repository || "").trim();
  if (!input || input.length > 200) throw httpError(422, "Enter a repository name or owner/repo.");
  const targetName = input.includes("/") ? validSlug(input).split("/")[1] : validName(input);
  const sourceSlug = input.includes("/") ? input.toLowerCase() : "";
  const variants = [...new Set([targetName, targetName.toLowerCase(), `${targetName}-scanner`, `${targetName}-tool`])];
  const found = new Map();
  for (const variant of variants) {
    const result = await github(`/search/repositories?q=${encodeURIComponent(`${variant} in:name`)}&per_page=15`, env);
    for (const item of result.items || []) {
      if (!item.full_name || item.full_name.toLowerCase() === sourceSlug) continue;
      found.set(item.full_name.toLowerCase(), item);
    }
  }

  const candidates = [...found.values()].map((item) => {
    const score = nameScore(targetName, item.name || "", Boolean(item.fork));
    const exact = normalize(item.name || "") === normalize(targetName);
    let classification = score.score < 50 ? "weak-similarity" : "name-collision";
    let risk = score.score < 50 ? "LOW" : "MEDIUM";
    const reasons = [...score.reasons];
    if (item.fork) {
      classification = "official-fork";
      risk = "INFO";
      reasons.unshift("GitHub marks this repository as a fork.");
    } else if (exact) {
      classification = "name-collision";
      risk = "LOW";
      reasons.unshift("Exact or normalized repository name match; manual review recommended.");
    }
    return {
      full_name: item.full_name,
      name: item.name,
      html_url: item.html_url,
      description: item.description,
      fork: Boolean(item.fork),
      created_at: item.created_at,
      pushed_at: item.pushed_at,
      stargazers_count: Number(item.stargazers_count || 0),
      default_branch: item.default_branch || "",
      license_key: item.license?.key || null,
      license_name: item.license?.name || null,
      readme_status: "not fetched",
      score: score.score,
      classification,
      risk_level: risk,
      reasons: [...new Set(reasons)],
    };
  }).sort((a, b) => (RISK_ORDER[b.risk_level] - RISK_ORDER[a.risk_level]) || (b.score - a.score) || (b.stargazers_count - a.stargazers_count));

  return { target: input, candidate_count: candidates.length, candidates };
}

async function github(path, env, allow404 = false) {
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "ForkSure-App" };
  if (env.GITHUB_TOKEN) headers.Authorization = `Bearer ${env.GITHUB_TOKEN}`;
  const response = await fetch(`https://api.github.com${path}`, { headers });
  if (allow404 && response.status === 404) return null;
  if (response.status === 404) throw httpError(404, "GitHub repository not found.");
  if (response.status === 403 || response.status === 429) {
    throw httpError(429, "GitHub rate limit reached. Try again later.");
  }
  if (!response.ok) throw httpError(502, `GitHub API returned ${response.status}.`);
  return response.json();
}

async function githubRepo(slug, env) {
  if (env.GITHUB_TOKEN) return github(`/repos/${slug}`, env);
  const result = await github(`/search/repositories?q=${encodeURIComponent(`repo:${slug}`)}&per_page=5`, env);
  const exact = (result.items || []).find((item) => item.full_name?.toLowerCase() === slug.toLowerCase());
  if (!exact) throw httpError(404, `GitHub repository ${slug} was not found.`);
  return exact;
}

async function githubOptional(path, env) {
  try {
    return await github(path, env, true);
  } catch (error) {
    if (Number(error?.status) === 404) return null;
    if ([429, 502].includes(Number(error?.status))) return { __unavailable: true };
    throw error;
  }
}

function repoSummary(repo, licenseData, readmeData) {
  const license = normalizeLicense(licenseData);
  return {
    name: repo.name,
    full_name: repo.full_name,
    html_url: repo.html_url,
    description: repo.description || "-",
    fork: Boolean(repo.fork),
    created_at: dateOnly(repo.created_at),
    pushed_at: dateOnly(repo.pushed_at),
    stargazers_count: Number(repo.stargazers_count || 0),
    default_branch: repo.default_branch || "-",
    license,
    license_label: license.found ? (license.spdx_id || license.name || license.key) : "Missing",
    readme: normalizeReadme(readmeData),
    readme_status: readmeData?.__unavailable
      ? "unknown"
      : readmeData
        ? (readmeData.path || readmeData.name || "found")
        : "missing",
  };
}

function normalizeLicense(data) {
  if (data?.__unavailable) {
    return { found: false, key: null, spdx_id: null, name: null, html_url: null, error: "License lookup unavailable." };
  }
  if (!data) return { found: false, key: null, spdx_id: null, name: null, html_url: null, error: null };
  return {
    found: true,
    key: data.license?.key || null,
    spdx_id: data.license?.spdx_id || null,
    name: data.license?.name || null,
    html_url: data.html_url || null,
    error: null,
  };
}

function normalizeReadme(data) {
  if (data?.__unavailable) {
    return { found: false, name: null, path: null, html_url: null, download_url: null, content_text: null, error: "README lookup unavailable." };
  }
  return {
    found: Boolean(data),
    name: data?.name || null,
    path: data?.path || null,
    html_url: data?.html_url || null,
    download_url: data?.download_url || null,
    content_text: decodeContent(data?.content),
    error: null,
  };
}

function compareLicenses(source, candidate) {
  const left = normalizeLicense(source);
  const right = normalizeLicense(candidate);
  if (!left.found) return { status: "unknown", severity: "low", summary: "Source license is unavailable." };
  if (right.error) return { status: "unknown", severity: "low", summary: "Candidate license could not be fetched." };
  if (!right.found) return { status: "missing", severity: "medium", summary: "Candidate license is missing." };
  const leftId = (left.spdx_id || left.key || left.name || "").toLowerCase();
  const rightId = (right.spdx_id || right.key || right.name || "").toLowerCase();
  if (leftId && leftId === rightId) return { status: "same", severity: "info", summary: `Candidate license matches source license ${left.spdx_id || left.name || left.key}.` };
  return { status: "changed", severity: "high", summary: `Candidate license differs from source (${left.spdx_id || left.name || left.key} vs ${right.spdx_id || right.name || right.key}).` };
}

function compareReadmes(sourceSlug, source, candidate) {
  if (source?.__unavailable) return { status: "unknown", severity: "low", summary: "Source README could not be fetched." };
  if (candidate?.__unavailable) return { status: "unknown", severity: "low", summary: "Candidate README could not be fetched." };
  if (!source) return { status: "unknown", severity: "low", summary: "Source README is unavailable." };
  if (!candidate) return { status: "missing-readme", severity: "medium", summary: "Candidate README is missing." };
  const content = decodeContent(candidate.content).toLowerCase();
  const [owner, repo] = sourceSlug.toLowerCase().split("/");
  const fullUrl = `https://github.com/${owner}/${repo}`;
  const preserved = content.includes(fullUrl) || content.includes(`${owner}/${repo}`) || nearby(content, owner, repo);
  return preserved
    ? { status: "preserved", severity: "info", summary: "Candidate README contains upstream attribution." }
    : { status: "missing-attribution", severity: "high", summary: "Candidate README does not show obvious upstream attribution." };
}

function nameScore(target, candidate, fork) {
  const left = normalize(target);
  const right = normalize(candidate);
  let score = 5;
  let reason = "Candidate has little name similarity.";
  if (candidate === target) [score, reason] = [95, "Exact repository name match under a different owner."];
  else if (left && left === right) [score, reason] = [90, "Repository name matches after case and punctuation normalization."];
  else if (left && right.includes(left)) [score, reason] = [70, "Candidate name contains the target repository name."];
  else if (similarity(left, right) >= 0.72) [score, reason] = [35, "Candidate name has weak fuzzy similarity."];
  if (fork && score < 90) score = Math.max(0, score - 20);
  return { score, risk_level: score >= 80 ? "HIGH" : score >= 50 ? "MEDIUM" : score >= 20 ? "LOW" : "INFO", reasons: [reason] };
}

function nameRisk(source, candidate, score) {
  if (candidate.fork) return riskItem("INFO", "Candidate is marked as a GitHub fork.");
  const sameOwner = source.full_name.split("/")[0].toLowerCase() === candidate.full_name.split("/")[0].toLowerCase();
  if (!sameOwner && normalize(source.name) === normalize(candidate.name)) return riskItem("HIGH", "Exact or normalized repository name match under a different owner.", score.reasons);
  if (score.score >= 50) return riskItem("MEDIUM", "Candidate name contains the source repository name.", score.reasons);
  if (score.score >= 20) return riskItem("LOW", "Weak fuzzy name similarity found.", score.reasons);
  return riskItem("INFO", "No meaningful name similarity found.", score.reasons);
}

function readmeRisk(candidate, score, comparison) {
  if (comparison.status === "preserved") return riskItem("INFO", comparison.summary);
  if (comparison.status === "missing-attribution") return riskItem(score.score >= 65 && !candidate.fork ? "HIGH" : "MEDIUM", comparison.summary);
  if (comparison.status === "missing-readme") return riskItem("MEDIUM", comparison.summary);
  return riskItem("LOW", comparison.summary);
}

function licenseRisk(comparison) {
  if (comparison.status === "same") return riskItem("INFO", comparison.summary);
  if (comparison.status === "changed") return riskItem("HIGH", comparison.summary);
  if (comparison.status === "missing") return riskItem("MEDIUM", comparison.summary);
  return riskItem("LOW", comparison.summary);
}

function overallRisk(breakdown) {
  const entries = Object.entries(breakdown).filter(([key]) => key !== "overall");
  let highest = "INFO";
  for (const [, item] of entries) if ((RISK_ORDER[item.risk_level] || 0) > (RISK_ORDER[highest] || 0)) highest = item.risk_level;
  const drivers = entries.filter(([, item]) => item.risk_level === highest).map(([key, item]) => `${key}: ${item.summary}`);
  return riskItem(highest, highest === "INFO" ? "No elevated hosted metadata signal was found." : `Overall risk is ${highest}.`, drivers);
}

function riskItem(risk_level, summary, reasons = []) { return { risk_level, summary, reasons }; }
function validSlug(value) {
  const slug = String(value || "").trim();
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/.test(slug)) throw httpError(422, "Expected repository in owner/repo format.");
  return slug;
}
function validName(value) {
  const name = String(value || "").trim();
  if (!/^[A-Za-z0-9._-]{1,100}$/.test(name)) throw httpError(422, "Enter a valid repository name.");
  return name;
}
function normalize(value) { return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, ""); }
function dateOnly(value) { return value ? String(value).split("T")[0] : "-"; }
function decodeContent(value) {
  if (!value) return "";
  try { return new TextDecoder().decode(Uint8Array.from(atob(String(value).replace(/\s/g, "")), (char) => char.charCodeAt(0))); } catch { return ""; }
}
function nearby(text, owner, repo) {
  const ownerAt = text.indexOf(owner);
  const repoAt = text.indexOf(repo);
  return ownerAt >= 0 && repoAt >= 0 && Math.abs(ownerAt - repoAt) <= 120;
}
function similarity(left, right) {
  if (!left && !right) return 1;
  const rows = Array.from({ length: left.length + 1 }, (_, index) => index);
  for (let j = 1; j <= right.length; j += 1) {
    let previous = rows[0]; rows[0] = j;
    for (let i = 1; i <= left.length; i += 1) {
      const held = rows[i];
      rows[i] = Math.min(rows[i] + 1, rows[i - 1] + 1, previous + (left[i - 1] === right[j - 1] ? 0 : 1));
      previous = held;
    }
  }
  return 1 - rows[left.length] / Math.max(left.length, right.length, 1);
}
function httpError(status, message) { const error = new Error(message); error.status = status; return error; }
function json(body, status = 200) { return withSecurityHeaders(new Response(JSON.stringify(body), { status, headers: JSON_HEADERS })); }
function withSecurityHeaders(response) {
  const next = new Response(response.body, response);
  next.headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'");
  next.headers.set("Referrer-Policy", "no-referrer");
  next.headers.set("X-Content-Type-Options", "nosniff");
  return next;
}
