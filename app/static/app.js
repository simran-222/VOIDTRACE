const app = document.querySelector("#app");
const state = {
  overview: null,
  bundles: {},
  audit: [],
  feed: null,
  error: "",
  notice: "",
  loading: false,
  busy: "",
  approver: sessionStorage.getItem("voidtrace.approver") || "Avery Chen",
  query: "",
  statusFilter: "",
  riskFilter: "",
  evidenceIncident: "",
  evidenceFocus: "",
  auditIncident: "",
  draft: "@voidtrace status",
  reportTitle: "",
  reportBody: "",
  focus: null,
  restoreFocus: false,
  confirm: "",
};

const NAV = [
  ["overview", "Overview"],
  ["incidents", "Incidents"],
  ["evidence", "Evidence"],
  ["response", "Response"],
  ["verification", "Verification"],
  ["switch", "Switch"],
  ["trust", "Trust"],
  ["settings", "Settings"],
];

function h(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (value !== null && value !== undefined && value !== false) node.setAttribute(key, String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function publicText(value) {
  return String(value ?? "")
    .replaceAll("VOIDTRACE", "VOIDTRACE")
    .replaceAll("SECURITY", "Enforcement");
}

function actorLabel(actor) {
  const name = String(actor || "");
  if (name === "VOIDTRACE") return "Investigator";
  if (name === "SECURITY") return "Enforcement";
  return name;
}

function parseRoute() {
  const raw = decodeURIComponent((location.hash || "").replace(/^#/, ""));
  if (!raw || raw === "/" || raw === "/intro") return { name: "intro" };
  if (raw === "/dashboard" || raw === "/overview") return { name: "overview" };
  if (raw === "/actions" || raw === "/response") return { name: "response" };
  if (raw === "/reports" || raw === "/audit" || raw === "/trust") return { name: "trust" };
  if (/^INC-[A-Za-z0-9]+$/.test(raw)) return { name: "incident", id: raw };
  const parts = raw.split("/").filter(Boolean);
  if (parts[0] === "incidents" && parts[1]) return { name: "incident", id: parts[1] };
  if (parts[0] === "dashboard") return { name: "overview" };
  if (NAV.some(([name]) => name === parts[0])) return { name: parts[0] };
  return { name: "intro" };
}

function go(path) {
  const next = path.startsWith("#") ? path : `#${path}`;
  if (location.hash === next) render();
  else location.hash = next;
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  let body = null;
  try { body = await response.json(); } catch (_error) { body = null; }
  if (!response.ok) {
    const detail = body && body.detail;
    const message = typeof detail === "string"
      ? detail
      : Array.isArray(detail)
        ? detail.map((item) => item.msg || "Invalid request").join(" ")
        : `Request failed (${response.status})`;
    throw new Error(publicText(message));
  }
  return body;
}

function incidents() {
  return (state.overview && state.overview.incidents) || [];
}

function bundleFor(id) {
  return state.bundles[id] || null;
}

function allApprovals() {
  return incidents().flatMap((item) => {
    const bundle = bundleFor(item.id);
    return bundle ? bundle.approvals.map((approval) => ({ ...approval, incidentTitle: item.title })) : [];
  });
}

function pendingApprovals() {
  return allApprovals().filter((item) => item.status === "PROPOSED" || item.status === "AWAITING_APPROVAL");
}

function assetOf(item) {
  const bundle = bundleFor(item.id);
  const impact = bundle && bundle.assessment && bundle.assessment.business_impact;
  if (impact && impact.service) {
    return [impact.service, impact.host]
      .filter(Boolean)
      .map(part => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" · ");
  }
  if (impact && impact.host) return impact.host;
  const approval = bundle && bundle.approvals[0];
  if (approval) return approval.resource;
  return "Not named";
}

function updatedOf(item) {
  const bundle = bundleFor(item.id);
  const timeline = bundle && bundle.timeline;
  const value = timeline && timeline.length
    ? timeline[timeline.length - 1].timestamp
    : item.created_at;

  if (!value) return "—";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  return new Intl.DateTimeFormat("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

function claimLabel(claim) {
  if (claim === "live_switch_round_trip") return "Live round-trip";
  if (claim === "live_switch_connected") return "Socket connected";
  return "Not connected";
}

function channelLabel(channel) {
  const value = String(channel || "");
  if (value === "switch" || value === "live_switch") return "Switch";
  if (!value) return "—";
  return "Local simulation — not a Switch delivery";
}

async function refresh() {
  state.loading = true;
  state.error = "";
  render();
  try {
    const route = parseRoute();
    const selected = route.name === "incident" ? route.id : "";
    const query = selected ? `?incident_id=${encodeURIComponent(selected)}` : "";
    const [overview, audit, feed] = await Promise.all([
      fetchJson(`/api/overview${query}`),
      fetchJson("/api/audit?limit=80"),
      fetchJson("/api/switch/feed"),
    ]);
    const bundles = {};
    if (overview.selected && overview.selected.incident) bundles[overview.selected.incident.id] = overview.selected;
    const missing = overview.incidents
      .map((item) => item.id)
      .filter((id) => !bundles[id])
      .slice(0, 20);
    const loaded = await Promise.all(missing.map(async (id) => {
      try { return await fetchJson(`/api/incidents/${encodeURIComponent(id)}`); }
      catch (_error) { return null; }
    }));
    for (const bundle of loaded) {
      if (bundle && bundle.incident) bundles[bundle.incident.id] = bundle;
    }
    state.overview = overview;
    state.bundles = bundles;
    state.audit = audit.events || [];
    state.feed = feed;
    if (!state.evidenceIncident && overview.incidents[0]) state.evidenceIncident = overview.incidents[0].id;
  } catch (error) {
    state.error = error.message || String(error);
  } finally {
    state.loading = false;
    render();
  }
}

function render() {
  const route = parseRoute();
  if (route.name === "intro") {
    app.replaceChildren(introPage());
    return;
  }
  const current = route.name === "incident" ? "incidents" : route.name;
  app.replaceChildren(h("div", { class: "app" },
    h("header", { class: "topbar" },
      h("a", { class: "mark", href: "#/" }, "VOIDTRACE"),
      h("nav", null, ...NAV.map(([name, label]) => h("a", {
        href: `#/${name}`,
        "aria-current": current === name ? "page" : null,
      }, label)))
    ),
    h("main", { class: "workspace" },
      state.error ? h("div", { class: "banner", role: "alert" }, state.error) : null,
      state.notice ? h("div", { class: "notice", role: "status" },
        h("span", null, state.notice),
        h("button", { class: "btn quiet", type: "button", onclick: () => { state.notice = ""; render(); } }, "Dismiss")
      ) : null,
      page(route)
    )
  ));
  if (state.restoreFocus && state.focus) {
    const node = document.getElementById(state.focus.id);
    if (node) {
      node.focus();
      if (node.setSelectionRange && state.focus.start != null) node.setSelectionRange(state.focus.start, state.focus.end);
    }
  }
  state.restoreFocus = false;
  if (state.evidenceFocus) {
    document.getElementById(`ev-${state.evidenceFocus}`)?.scrollIntoView({ block: "center" });
  }
}

function page(route) {
  if (!state.overview) {
    return h("div", { class: "page" }, h("h1", null, state.loading ? "Loading records" : "VOIDTRACE"), h("p", null, state.loading ? "Reading the local database." : "The overview could not be loaded."));
  }
  if (route.name === "incidents") return incidentsPage();
  if (route.name === "incident") return incidentPage(route.id);
  if (route.name === "evidence") return evidencePage();
  if (route.name === "response") return actionsPage();
  if (route.name === "verification") return verificationPage();
  if (route.name === "switch") return switchPage();
  if (route.name === "trust") return reportsPage();
  if (route.name === "settings") return settingsPage();
  return dashboardPage();
}

function nodes() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "nodes");
  svg.setAttribute("viewBox", "0 0 86 28");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M8 18 C 20 6, 30 24, 44 14 S 66 6, 78 16");
  path.setAttribute("fill", "none");
  path.setAttribute("stroke", "#849AAD");
  path.setAttribute("stroke-width", "1.8");
  path.setAttribute("stroke-linecap", "round");
  svg.append(path);
  for (const [cx, fill] of [[8, "#B1C7D4"], [44, "#5E1C23"], [78, "#605246"]]) {
    const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    dot.setAttribute("cx", String(cx));
    dot.setAttribute("cy", cx === 44 ? "14" : cx === 8 ? "18" : "16");
    dot.setAttribute("r", "4");
    dot.setAttribute("fill", fill);
    svg.append(dot);
  }
  return svg;
}

function stamp(status) {
  const text = String(status || "—");
  const hot = /CRITICAL|HIGH|FAILED|DENIED|AWAITING|UNVERIFIED/.test(text);
  const quiet = !hot && /NONE|RESOLVED|VERIFIED|INSUFFICIENT/.test(text);
  const label = text.replaceAll("_", " ").toLowerCase()
    .replace(/^./, char => char.toUpperCase());

  return h("span", {
    class: `stamp${hot ? " hot" : ""}${quiet ? " quiet" : ""}`
  }, label);
}

function squiggle() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "squiggle");
  svg.setAttribute("viewBox", "0 0 148 18");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M2 11 C 18 2, 28 16, 46 9 S 78 2, 96 10 128 16, 146 7");
  path.setAttribute("fill", "none");
  path.setAttribute("stroke", "#A1947F");
  path.setAttribute("stroke-width", "2.2");
  path.setAttribute("stroke-linecap", "round");
  svg.append(path);
  return svg;
}

function introPage() {
  return h("section", { class: "intro" },
    h("div", { class: "intro-copy" },
      h("p", { class: "kicker" }, "A desk for incidents that should not be guessed"),
      h("h1", null, h("span", null, "VOID"), h("span", null, "TRACE")),
      squiggle(),
      h("p", { class: "tagline" }, "Trust nothing. Verify everything."),
      h("p", { class: "explain" }, "VOIDTRACE keeps a security conclusion tied to evidence, asks a person before a sensitive simulated change, and checks the result against the simulated world."),
      h("a", { class: "btn primary enter", href: "#/overview" }, "Enter VOIDTRACE")
    ),
    h("aside", { class: "intro-panel" },
      h("article", null, h("h2", null, "Evidence, then a belief"), h("p", null, "A fact cites stored records. A rumour, a contradiction, and an instruction hidden in a log stay out of the score.")),
      h("article", null, h("h2", null, "A person, then a change"), h("p", null, "The desk can propose. It cannot treat its own recommendation as permission.")),
      h("article", null, h("h2", null, "A check, then resolved"), h("p", null, "An action is finished only when an independent read of the simulated state matches the intent."))
    )
  );
}

function overviewPhrase(value) {
  const text = String(value ?? "").trim().replaceAll("_", " ").toLowerCase();
  if (!text) return "Unknown";
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function folioRule() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "folio-rule");
  svg.setAttribute("viewBox", "0 0 220 18");
  svg.setAttribute("aria-hidden", "true");
  const line = document.createElementNS("http://www.w3.org/2000/svg", "path");
  line.setAttribute("d", "M4 9 H168");
  line.setAttribute("fill", "none");
  line.setAttribute("stroke", "#849AAD");
  line.setAttribute("stroke-width", "1.25");
  svg.append(line);
  for (const [cx, fill, r] of [[4, "#B1C7D4", 3.2], [86, "#605246", 2.2], [168, "#5E1C23", 4]]) {
    const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    dot.setAttribute("cx", String(cx));
    dot.setAttribute("cy", "9");
    dot.setAttribute("r", String(r));
    dot.setAttribute("fill", fill);
    svg.append(dot);
  }
  return svg;
}

function scoreNote(value) {
  if (value == null || value === "") return "";
  const number = Number(value);
  if (Number.isNaN(number)) return "";
  const shown = Number.isInteger(number) ? String(number) : number.toFixed(1);
  return `Score ${shown}`;
}

function dashboardPage() {
  const health = state.overview.health;
  const core = health.switch_core;
  const rows = incidents();
  const pending = pendingApprovals();
  const ledgerOk = Boolean(health.database.audit_integrity_verified);
  const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 };
  const waitingIds = new Set(pending.map((item) => item.incident_id).filter(Boolean));
  const ordered = rows
    .map((item, index) => ({ item, index }))
    .sort((a, b) => {
      const score = (entry) => (rank[entry.item.risk_level] || 0) * 10
        + (waitingIds.has(entry.item.id) ? 3 : 0)
        + (entry.item.status !== "RESOLVED" ? 1 : 0);
      return score(b) - score(a) || a.index - b.index;
    })
    .map((entry) => entry.item);
  const lead = ordered[0];
  const rest = ordered.slice(1);
  const open = rows.filter((item) => item.status !== "RESOLVED").length;
  const resolved = rows.length - open;
  const riskBits = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    .map((level) => {
      const count = rows.filter((item) => (item.risk_level || "NONE") === level).length;
      return count ? `${count} ${overviewPhrase(level).toLowerCase()}` : "";
    })
    .filter(Boolean);
  const riskText = riskBits.length > 1
    ? `${riskBits.slice(0, -1).join(", ")} and ${riskBits[riskBits.length - 1]}`
    : (riskBits[0] || "");
  const situation = rows.length
    ? `${open} open incident${open === 1 ? "" : "s"}${resolved ? `, ${resolved} resolved` : ""}${riskText ? ` · Assessed risk across all incidents: ${riskText}` : ""}.`
    : "No incidents on this database.";
  const asset = lead ? assetOf(lead) : "";
  const leadNotes = lead
    ? [lead.severity ? `Severity ${overviewPhrase(lead.severity)}` : "", asset && asset !== "Not named" ? asset.split(" · ").map(part => part.charAt(0).toUpperCase() + part.slice(1)).join(" · ") : "", scoreNote(lead.risk_score)].filter(Boolean).join("  ·  ")
    : "";
  return h("div", { class: "page dashboard" },
    h("div", { class: "spread" },
      lead
        ? h("a", { class: "folio", href: `#/incidents/${lead.id}` },
            h("p", { class: "folio-kicker" }, "Today"),
            h("h1", null, lead.title),
            folioRule(),
            h("p", { class: "folio-meta" },
              h("span", { class: lead.risk_level === "HIGH" || lead.risk_level === "CRITICAL" ? "critical" : "" }, lead.risk_level ? overviewPhrase(lead.risk_level) : "Unscored"),
              `  ·  ${overviewPhrase(lead.status)}`
            ),
            leadNotes ? h("p", { class: "folio-note" }, leadNotes) : null,
            h("p", { class: "mono" }, lead.id)
          )
        : h("div", { class: "folio" },
            h("p", { class: "folio-kicker" }, "Today"),
            h("h1", null, "No open incident"),
            h("p", null, "No incidents yet. Record a report, or load the labelled demonstration from Settings.")
          ),
      h("aside", { class: "margin-note", "aria-label": "System status" },
        h("p", { class: "anno" }, "System"),
        h("div", { class: "plate" }, h("strong", { class: ledgerOk ? "" : "critical" }, overviewPhrase(health.status))),
        h("p", null, ledgerOk ? "Audit ledger verified." : "Audit ledger failed."),
        h("p", null, claimLabel(core.connection_claim)),
        h("p", null, core.real_switch_proven ? "Live round-trip proven." : "Live Switch is not proven."),
        h("p", { class: "situation" }, situation)
      ),
      rest.length
        ? h("section", { class: "also" },
            h("h2", null, "Also open"),
            ...rest.map((item, index) => h("a", { href: `#/incidents/${item.id}` },
              h("strong", null, item.title),
              h("span", null, `${item.risk_level ? overviewPhrase(item.risk_level) : "Unscored"}  ·  ${overviewPhrase(item.status)}`)
            ))
          )
        : h("section", { class: "also" }),
      h("section", { class: pending.length ? "decision" : "decision calm" },
        h("h2", null, pending.length === 1 ? "Needs a person" : pending.length ? `${pending.length} need a person` : "Nothing is waiting for a person"),
        ...pending.map((item) => h("a", { href: "#/response" },
          h("strong", null, prettyAction(item.action).replace(/\b\w/g, c => c.toUpperCase())),
          h("span", null, `${item.resource.replace(/^process:/i, "Process: ").replace(/\b\w/g, c => c.toUpperCase())}  ·  ${overviewPhrase(item.status).replace(/\b\w/g, c => c.toUpperCase())}`)
        ))
      )
    )
  );
}

function impactOf(item) {
  const impact = bundleFor(item.id) && bundleFor(item.id).assessment && bundleFor(item.id).assessment.business_impact;
  if (!impact) return "Not assessed";
  if (!impact.known) return "Unknown";
  return impact.service || impact.host || "Assessed";
}

function incidentsPage() {
  const rows = filteredIncidents();
  const statuses = [...new Set(incidents().map((item) => item.status))];
  const risks = [...new Set(incidents().map((item) => item.risk_level || "NONE"))];
  return h("div", { class: "page register" },
    nodes(),
    h("p", { class: "eyebrow" }, "Incidents"),
    h("h1", null, "What is open"),
    h("p", { class: "lede" }, "Each row is a separate investigation. Opening one does not change another."),
    h("div", { class: "filters" },
      field("Search", h("input", { id: "incident-search", type: "search", value: state.query, placeholder: "Title or Identifier", oninput: keep("query", true) })),
      field("Status", select("statusFilter", state.statusFilter, ["", ...statuses],
  (value) => { state.statusFilter = value; render(); },
  Object.fromEntries(statuses.map(status => [
    status,
    status.replaceAll("_", " ").toLowerCase()
      .replace(/\b\w/g, char => char.toUpperCase())
  ])))),
      field("Risk", select("riskFilter", state.riskFilter, ["", ...risks], (value) => { state.riskFilter = value; render(); }))
    ),
    rows.length ? h("table", null,
      h("thead", null, h("tr", null, ["Incident", "ID", "Severity", "Status", "Asset", "Risk", "Updated"].map((name) => h("th", null, name)))),
      h("tbody", null, rows.map((item) => h("tr", { class: "clickable", onclick: () => go(`/incidents/${item.id}`) },
        h("td", null, h("strong", null, item.title)),
        h("td", { class: "mono" }, item.id),
        h("td", null, item.severity || "—"),
        h("td", null, stamp(item.status)),
        h("td", null, assetOf(item)),

        h("td", null, item.risk_score == null ? "Unscored" : `${item.risk_level} · ${item.risk_score}`),
        h("td", { class: "mono" }, updatedOf(item))
      )))
    ) : h("p", null, "No incident matches this filter."),
    h("section", { class: "section" },
      h("h2", null, "Record a report"),
      h("p", { class: "muted" }, "The report is stored as untrusted input. It does not prove what happened."),
      h("div", { class: "toolbar" },
        field("Title", h("input", { id: "report-title", type: "text", value: state.reportTitle, oninput: keep("reportTitle") })),
        field("Severity", select("newSeverity", state.newSeverity || "MEDIUM", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], (value) => { state.newSeverity = value; }))
      ),
      field("Report", h("textarea", { id: "report-body", value: state.reportBody, oninput: keep("reportBody") })),
      h("div", { class: "actions" },
        h("button", { class: "btn primary", type: "button", disabled: state.busy === "create" ? true : null, onclick: createIncident }, state.busy === "create" ? "Recording…" : "Create and investigate")
      )
    )
  );
}

function filteredIncidents() {
  const query = state.query.trim().toLowerCase();
  return incidents().filter((item) => {
    if (state.statusFilter && item.status !== state.statusFilter) return false;
    if (state.riskFilter && (item.risk_level || "NONE") !== state.riskFilter) return false;
    if (!query) return true;
    return `${item.id} ${item.title} ${item.status} ${assetOf(item)}`.toLowerCase().includes(query);
  });
}

function incidentPage(id) {
  const bundle = bundleFor(id);
  if (!bundle) {
    return h("div", { class: "page" },
      h("h1", null, "Incident not on this database"),
      h("p", null, id),
      h("a", { href: "#/incidents" }, "Back to incidents")
    );
  }
  const incident = bundle.incident;
  const assessment = bundle.assessment;
  const groups = groupFindings(bundle.findings);
  const impact = assessment && assessment.business_impact;
  return h("div", { class: "page trail" },
    h("a", { class: "back", href: "#/incidents" }, "All incidents"),
    h("p", { class: "eyebrow" }, "Investigation"),
    h("h1", null, incident.title),
    h("p", { class: "lede" }, assessment ? publicText(assessment.headline) : "Investigation has not produced an assessment yet."),
    h("div", { class: "meta-line" },
      h("span", { class: "mono" }, incident.id),
      h("span", null, incident.status),
      h("span", null, `Severity ${incident.severity}`),
      h("span", null, assessment ? `Risk ${assessment.risk_level} · ${assessment.risk_score}` : "Unscored"),
      h("span", null, assetOf({ id }))
    ),
    h("section", null,
      h("h2", null, "The report"),
      h("p", { class: "muted" }, "Untrusted. A human message is not evidence."),
      h("p", { class: "quote" }, (incident.metadata && incident.metadata.report) || incident.title)
    ),
    h("details", { open: true },
      h("summary", null, "What is known, guessed, and missing"),
      h("section", { class: "finding-grid" },
        findingColumn("Confirmed facts", "A fact is shown here only when the investigation cited stored evidence.", groups.facts, true),
        findingColumn("Interpretations", "A single source, or a claim that disagrees with telemetry, stays an interpretation.", groups.hypotheses, false),
        findingColumn("Not established", "Missing or uncorroborated claims are left unknown.", groups.unknowns, false)
      )
    ),
    h("details", null,
      h("summary", null, "Risk and business impact"),
      assessment ? h("p", { class: "muted" }, "Only corroborated facts raise the score. Interpretations do not.") : h("p", null, "No assessment is stored."),
      ...(assessment ? (assessment.drivers || []).map((driver) => h("p", null, `${driver.factor} · +${driver.points}`)) : []),
      impact ? h("p", null, impact.recommendation || impact.statement || "Business impact is unknown.") : null,
      impact && impact.if_credential_disabled ? h("p", null, impact.if_credential_disabled) : null,
      impact && impact.if_host_isolated ? h("p", null, impact.if_host_isolated) : null,
      ...(assessment ? (assessment.suppressed_actions || []).map((item) => h("p", { class: "muted" }, `Not proposed: ${item.action} on ${item.resource}. ${item.reason}`)) : [])
    ),
    h("details", { open: true },
      h("summary", null, "Proposed response"),
      bundle.approvals.length ? bundle.approvals.map((item) => approvalSummary(item)) : h("p", null, "No response is proposed. Insufficient evidence does not produce an action."),
      h("p", null, h("a", { href: "#/response" }, "Open approvals"))
    ),
    h("details", null,
      h("summary", null, "Permission decisions"),
      h("p", { class: "muted" }, "Every simulated tool call is allowed or denied by the backend before it runs."),
      decisionsTable(bundle.decisions)
    ),
    h("details", null,
      h("summary", null, "Verification"),
      h("p", { class: "muted" }, "A successful executor reply is not treated as the outcome. The checker reads simulated state itself."),
      bundle.approvals.length ? bundle.approvals.map((item) => verificationBlock(item)) : h("p", null, "Nothing has been submitted for verification."),
      h("div", { class: "actions" },
        h("button", { class: "btn", type: "button", disabled: state.busy === "investigate" ? true : null, onclick: () => investigate(id) }, state.busy === "investigate" ? "Investigating…" : "Run investigation again")
      )
    )
  );
}

function groupFindings(findings) {
  const groups = { facts: [], hypotheses: [], unknowns: [] };
  for (const finding of findings || []) {
    const cited = Array.isArray(finding.evidence_ids) && finding.evidence_ids.length > 0;
    if (finding.kind === "fact" && cited) groups.facts.push(finding);
    else if (finding.kind === "hypothesis") groups.hypotheses.push(finding);
    else groups.unknowns.push(finding);
  }
  return groups;
}

function findingColumn(title, note, items, linked) {
  return h("div", { class: "column" },
    h("h3", null, title),
    h("p", { class: "muted" }, note),
    items.length ? items.map((item) => h("article", { class: "item" },
      h("p", null, publicText(item.statement)),
      h("p", { class: "mono" }, `Confidence ${Number(item.confidence).toFixed(2)} · ${publicText(item.confidence_reason || "")}`),
      item.uncertainty ? h("p", { class: "muted" }, publicText(item.uncertainty)) : null,
      linked ? evidenceChips(item.evidence_ids) : h("p", { class: "mono" }, item.evidence_ids && item.evidence_ids.length ? `Cites ${item.evidence_ids.join(", ")}` : "No evidence cited")
    )) : h("p", null, "None in this investigation.")
  );
}

function evidenceChips(ids) {
  return h("div", { class: "chips" }, ...(ids || []).map((id) => h("button", {
    class: "chip",
    type: "button",
    onclick: () => { state.evidenceFocus = id; go("/evidence"); },
  }, id)));
}

function approvalSummary(item) {
  return h("article", { class: "item" },
    h("strong", null, `${item.action} · ${item.resource}`),
    h("p", null, item.justification),
    h("p", { class: "mono" }, `${item.id} · ${item.status} · risk ${item.risk}`),
    evidenceChips(item.evidence_ids)
  );
}

function verificationBlock(item) {
  const verification = item.verification;
  return h("article", { class: "item" },
    h("strong", null, `${item.id} · ${item.verification_result || item.status}`),
    h("p", null, verification ? verification.reason : "Verification has not confirmed this action."),
    verification ? h("p", { class: "mono" }, `Observed state ${JSON.stringify(verification.actual)} · executor claim ignored: ${verification.ignored_executor_claim}`) : null
  );
}

function decisionsTable(decisions) {
  if (!decisions.length) return h("p", null, "No permission decision is stored for this incident.");
  return h("div", { style: "overflow-x:auto" }, h("table", null,
    h("thead", null, h("tr", null, ["When", "Actor", "Operation", "Resource", "Result", "Reason"].map((name) => h("th", null, name)))),
    h("tbody", null, decisions.map((item) => h("tr", null,
      h("td", { class: "mono" }, shortTime(item.created_at)),
      h("td", null, actorLabel(item.actor)),
      h("td", { class: "mono" }, item.operation),
      h("td", { class: "mono" }, item.resource),
      h("td", { class: item.allowed ? "" : "critical" }, item.allowed ? "Allowed" : "Denied"),
      h("td", null, publicText(item.reason))
    )))
  ));
}

function evidencePage() {
  const options = incidents();
  const selected = state.evidenceIncident || (options[0] && options[0].id) || "";
  const bundle = selected ? bundleFor(selected) : null;
  const records = bundle ? bundle.evidence : [];
  return h("div", { class: "page sheets" },
    nodes(),
    h("p", { class: "eyebrow" }, "Evidence"),
    h("h1", null, "What was actually collected"),
    h("p", { class: "lede" }, "Findings on the investigation page cite these identifiers. Nothing here is invented by the page."),
    options.length ? field("Incident", select("evidenceIncident", selected, options.map((item) => item.id), (value) => {
      state.evidenceIncident = value;
      state.evidenceFocus = "";
      render();
    }, options.reduce((map, item) => { map[item.id] = item.title; return map; }, {}))) : null,
    !bundle ? h("p", null, "Choose an incident that exists on this database.") : null,
    bundle && !records.length ? h("p", null, "This incident has no collected evidence.") : null,
    ...records.map((item) => h("article", { class: "item", id: `ev-${item.id}` },
      h("div", { class: "meta-line" },
        h("span", { class: "mono" }, item.id),
        h("span", null, item.tool_name || item.kind || "record"),
        h("span", null, item.trust || "untrusted"),
        h("span", { class: "mono" }, item.collected_at || "—")
      ),
      h("p", null, `Source ${item.source || "—"} · Incident ${item.incident_id}`),
      h("p", { class: "mono" }, `sha256 ${item.content_hash || "—"}`),
      citedBy(item.id, bundle),
      h("pre", { class: "record" }, JSON.stringify(item.data, null, 2))
    ))
  );
}

function citedBy(evidenceId, bundle) {
  const hits = (bundle.findings || []).filter((item) => (item.evidence_ids || []).includes(evidenceId));
  if (!hits.length) return h("p", { class: "muted" }, "No finding cites this record.");
  return h("p", null, `Cited by ${hits.map((item) => item.kind).join(", ")}: ${hits.map((item) => publicText(item.statement)).join(" ")}`);
}

function verificationPage() {
  const items = allApprovals();
  return h("div", { class: "page compare" },
    nodes(),
    h("p", { class: "eyebrow" }, "Verification"),
    h("h1", null, "What was actually observed"),
    h("p", { class: "lede" }, "A completed request is not a resolved incident. These outcomes come from an independent read of the simulated world."),
    items.length ? items.map((item) => h("article", { class: "item" },
      h("h2", null, prettyAction(item.action).replace(/\b\w/g, c => c.toUpperCase())),
      h("p", { class: "mono" }, `${item.id} · ${item.incidentTitle}`),
      h("p", null, `Attempted state ${item.status}. Verification ${item.verification_result || "not confirmed"}.`),
      verificationBlock(item),
      h("a", { href: `#/incidents/${item.incident_id}` }, "Open investigation")
    )) : h("p", null, "No action has been proposed, so nothing is waiting to be verified.")
  );
}

function actionsPage() {
  const items = allApprovals();
  return h("div", { class: "page desk" },
    nodes(),
    h("p", { class: "eyebrow" }, "Response"),
    h("h1", null, "Approval before action"),
    h("p", { class: "lede" }, "High-risk simulated changes stay proposed until a person decides. The page cannot mark an action successful; execution and verification come back from the server."),
    field("Approver", h("input", {
      id: "approver-name",
      type: "text",
      value: state.approver,
      oninput: (event) => {
        state.approver = event.target.value;
        sessionStorage.setItem("voidtrace.approver", state.approver);
        remember(event);
      },
    })),
    h("p", { class: "muted" }, "The decision is recorded as a local dashboard decision unless Switch is actually connected."),
    items.length ? items.map((item) => h("article", { class: "action" },
      h("div", null,
        h("h2", null, `${prettyAction(item.action).replace(/\b\w/g, c => c.toUpperCase())}`),
        h("p", null, item.justification),
        h("p", { class: "mono" }, `${item.id} · ${item.incident_id} · ${item.incidentTitle}`),
        h("div", { class: "meta-line" },
          h("span", null, `Target ${item.resource}`),
          h("span", null, `Risk ${item.risk}`),
          h("span", null, stamp(item.status)),
          h("span", null, item.verification_result ? `Verification ${item.verification_result}` : "Verification not confirmed")
        ),
        h("p", { class: "mono" }, `Channel ${channelLabel(item.decision_channel || item.notified_via)} · approver ${item.approver || "—"}`),
        evidenceChips(item.evidence_ids),
        item.verification ? h("p", null, item.verification.reason) : null
      ),
      h("div", { class: "actions" }, actionButtons(item))
    )) : h("p", null, "No proposed action is stored.")
  );
}

function actionButtons(item) {
  const waiting = item.status === "PROPOSED" || item.status === "AWAITING_APPROVAL";
  const busy = Boolean(state.busy);
  if (waiting) {
    const armed = state.confirm === `reject:${item.id}`;
    return [
      h("button", { class: "btn primary", type: "button", disabled: busy ? true : null, onclick: () => decide(item, "approve") }, "Approve"),
      h("button", { class: "btn", type: "button", disabled: busy ? true : null, onclick: () => {
        if (!armed) { state.confirm = `reject:${item.id}`; render(); return; }
        decide(item, "reject");
      } }, armed ? "Confirm reject" : "Reject"),
    ];
  }
  if (item.status === "APPROVED") {
    const armed = state.confirm === `execute:${item.id}`;
    return [h("button", {
      class: "btn primary",
      type: "button",
      disabled: busy ? true : null,
      onclick: () => {
        if (!armed) { state.confirm = `execute:${item.id}`; render(); return; }
        execute(item);
      },
    }, state.busy === item.id ? "Executing…" : armed ? "Confirm execution" : "Execute simulated action")];
  }
  return [h("span", { class: "muted" }, "No further action from this desk.")];
}

function switchPage() {
  const core = state.overview.health.switch_core;
  const messages = (state.feed && state.feed.messages) || [];
  return h("div", { class: "page linkup" },
    nodes(),
    h("p", { class: "eyebrow" }, "Switch"),
    h("h1", null, claimLabel(core.connection_claim)),
    h("p", { class: "lede" }, core.honesty),
    h("div", { class: "meta-line" },
      h("span", null, core.real_switch_proven ? "Live connection proven" : "Live connection not proven"),
      h("span", null, core.registration_token_configured ? "Registration token is configured and hidden" : "Registration token is not configured"),
      h("span", { class: "mono" }, core.agent_id ? `Agent ${core.agent_id}` : "Agent not registered"),
      h("span", { class: "mono" }, `Received ${core.messages_received} · sent ${core.messages_sent}`)
    ),
    h("p", { class: "mono" }, `Target ${core.target_server} · adapter ${core.status}`),
    core.last_error ? h("p", { class: "critical" }, publicText(core.last_error)) : h("p", { class: "muted" }, "No adapter error is stored."),
    core.last_connected_at ? h("p", { class: "mono" }, `Last connected ${core.last_connected_at}`) : null,
    h("section", { class: "sim-box" },
      h("h2", null, "Local simulation"),
      h("p", null, "Messages typed here stay on this machine. They exercise the same operator commands, and they are not a Switch connection."),
      h("textarea", { id: "sim-body", value: state.draft, oninput: keep("draft") }),
      h("div", { class: "actions", style: "margin-top:10px" },
        h("button", { class: "btn", type: "button", disabled: state.busy === "sim" ? true : null, onclick: sendSimulation }, state.busy === "sim" ? "Sending…" : "Send as local simulation")
      )
    ),
    h("section", { class: "section" },
      h("h2", null, "Transcript"),
      messages.length ? messages.slice().reverse().map((item) => h("article", { class: "item" },
        h("p", { class: "mono" }, `${channelLabel(item.channel)} · live=${item.real_switch ? "yes" : "no"}`),
        h("pre", { class: "record" }, item.content || "")
      )) : h("p", null, "No outbound transcript is stored in this session.")
    )
  );
}

function reportsPage() {
  const health = state.overview.health;
  const controls = state.overview.controls || [];
  const selected = state.auditIncident;
  const events = state.audit.filter((event) => !selected || event.incident_id === selected || !event.incident_id);
  const operations = health.performance.operations || [];
  return h("div", { class: "page ledger" },
    nodes(),
    h("p", { class: "eyebrow" }, "Trust"),
    h("h1", null, "History you can re-check"),
    h("div", { class: "stats" },
      h("div", null, h("b", null, String(incidents().length)), "Incidents"),
      h("div", null, h("b", null, String(allApprovals().filter((item) => item.verification_result === "VERIFIED").length)), "Verified actions"),
      h("div", null, h("b", { class: "critical" }, String(allApprovals().filter((item) => item.status === "FAILED" || item.verification_result === "FAILED").length)), "Failed checks"),
      h("div", null, h("b", null, String((state.overview.controls || []).filter((item) => item.observed).length)), "Safeguards observed")
    ),
    h("p", { class: "lede" }, health.database.audit_integrity_details),
    h("p", null, health.database.evidence_integrity_details),
    h("div", { class: "actions" },
      h("button", { class: "btn", type: "button", disabled: state.busy === "audit" ? true : null, onclick: checkIntegrity }, state.busy === "audit" ? "Checking…" : "Re-check integrity")
    ),
    h("section", { class: "section" },
      h("h2", null, "Audit events"),
      field("Incident", select("auditIncident", selected, ["", ...incidents().map((item) => item.id)], (value) => { state.auditIncident = value; render(); }, { "": "All incidents" })),
      events.length ? h("div", { style: "overflow-x:auto" }, h("table", null,
        h("thead", null, h("tr", null, ["Time", "Incident", "Actor", "Action"].map((name) => h("th", null, name)))),
        h("tbody", null, events.slice().reverse().map((event) => h("tr", null,
          h("td", { class: "mono" }, event.timestamp),
          h("td", { class: "mono" }, event.incident_id || "—"),
          h("td", null, actorLabel(event.actor)),
          h("td", null, publicText(event.action))
        )))
      )) : h("p", null, "No audit events match.")
    ),
    h("section", { class: "section" },
      h("h2", null, "Safeguards"),
      h("p", { class: "muted" }, "Observed means this database already contains the behaviour. Armed means the control is present and has not been exercised here."),
      ...controls.map((item) => h("article", { class: "safeguard" },
        h("div", { class: item.observed ? "mark-observed" : "mark-armed" }, item.observed ? "Observed" : "Armed"),
        h("div", null, h("strong", null, publicText(item.name)), h("p", { class: "muted" }, publicText(item.detail)))
      ))
    ),
    h("section", { class: "section" },
      h("h2", null, "Performance"),
      h("p", null, `Memory ${health.performance.current_memory_kb} KB now, ${health.performance.peak_memory_kb} KB peak.`),
      operations.length ? operations.slice(-8).reverse().map((item) => h("p", { class: "mono" }, `${item.name} · ${item.duration_ms} ms`)) : h("p", null, "No timings stored yet.")
    )
  );
}

function settingsPage() {
  const health = state.overview.health;
  return h("div", { class: "page quiet" },
    nodes(),
    h("p", { class: "eyebrow" }, "Settings"),
    h("h1", null, "What this copy is using"),
    h("div", { class: "meta-line" },
      h("span", null, `${health.app} ${health.version}`),
      h("span", null, `Database ${health.database.journal_mode}`),
      h("span", null, `${health.database.incidents_count} incidents`),
      h("span", null, `${health.database.audit_events_count} audit events`)
    ),
    h("p", null, health.switch_core.honesty),
    h("p", { class: "muted" }, health.switch_core.registration_token_configured ? "A Switch registration token is configured. It is not shown here." : "No Switch registration token is configured, so live registration stays off."),
    h("section", { class: "section" },
      h("h2", null, "Local approver"),
      h("p", { class: "muted" }, "Stored in this browser only. The server still rejects an automated approver name."),
      field("Name", h("input", {
        id: "approver-name",
        type: "text",
        value: state.approver,
        oninput: (event) => {
          state.approver = event.target.value;
          sessionStorage.setItem("voidtrace.approver", state.approver);
          remember(event);
        },
      }))
    ),
    h("section", { class: "section" },
      h("h2", null, "Demonstration"),
      h("p", null, "Loads Operation ShadowCredential into the current database. Existing incidents and the audit ledger stay. The simulated world is rebuilt. This is not a live Switch session."),
      h("button", { class: "btn primary", type: "button", disabled: state.busy === "demo" ? true : null, onclick: runDemo }, state.busy === "demo" ? "Loading demonstration…" : "Load demonstration incidents")
    ),
    h("section", { class: "section" },
      h("h2", null, "Refresh"),
      h("button", { class: "btn", type: "button", onclick: () => refresh() }, state.loading ? "Refreshing…" : "Reload from the server")
    )
  );
}

function field(label, control) {
  return h("label", null, label, control);
}

function select(id, value, values, onchange, labels) {
  return h("select", { id, onchange: (event) => onchange(event.target.value) },
    ...values.map((item) => h("option", { value: item, selected: item === value ? true : null }, (labels && labels[item]) || item || "Any"))
  );
}

function keep(key, rerender) {
  return (event) => {
    state[key] = event.target.value;
    remember(event);
    if (rerender) render();
  };
}

function remember(event) {
  state.focus = { id: event.target.id, start: event.target.selectionStart, end: event.target.selectionEnd };
  state.restoreFocus = true;
}

function prettyAction(action) {
  const names = {
    "response.disable_credential": "Disable credential",
    "response.terminate_process": "Terminate process",
    "response.isolate_host": "Isolate host",
  };
  return names[action] || String(action || "Action").replaceAll("_", " ");
}

function shortTime(value) {
  const text = String(value || "");
  return text.length > 19 ? text.slice(0, 19) : text;
}

async function runDemo() {
  state.busy = "demo";
  state.notice = "";
  render();
  try {
    const body = await fetchJson("/api/demo/shadow-credential", { method: "POST" });
    state.notice = body.note || "Demonstration loaded.";
    await refresh();
    go(`/incidents/${body.shadow_incident_id}`);
  } catch (error) {
    state.error = error.message || String(error);
    state.busy = "";
    render();
  } finally {
    state.busy = "";
    if (state.overview) render();
  }
}

async function createIncident() {
  const title = state.reportTitle.trim();
  const report = state.reportBody.trim();
  if (title.length < 1) {
    state.error = "A title is required.";
    render();
    return;
  }
  state.busy = "create";
  state.error = "";
  render();
  try {
    const created = await fetchJson("/api/incidents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, severity: state.newSeverity || "MEDIUM", report: report || title }),
    });
    await fetchJson(`/api/incidents/${created.id}/investigate`, { method: "POST" });
    state.reportTitle = "";
    state.reportBody = "";
    state.notice = "Incident recorded and investigated. The report itself was not treated as proof.";
    await refresh();
    go(`/incidents/${created.id}`);
  } catch (error) {
    state.error = error.message || String(error);
    state.busy = "";
    render();
  } finally {
    state.busy = "";
    if (state.overview) render();
  }
}

async function investigate(id) {
  state.busy = "investigate";
  state.error = "";
  render();
  try {
    const body = await fetchJson(`/api/incidents/${id}/investigate`, { method: "POST" });
    state.notice = body.real_switch_proven ? "Investigation published through Switch." : "Investigation updated. The update was not sent through a proven Switch connection.";
    await refresh();
  } catch (error) {
    state.error = error.message || String(error);
    state.busy = "";
    render();
  } finally {
    state.busy = "";
    if (state.overview) render();
  }
}

async function decide(item, decision) {
  const approver = state.approver.trim();
  if (approver.length < 2) {
    state.error = "Enter the approver's name before deciding.";
    render();
    return;
  }
  state.busy = item.id;
  state.error = "";
  render();
  try {
    const body = await fetchJson(`/api/incidents/${item.incident_id}/approvals/${item.id}/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision, approver, comment: "Dashboard decision", channel: "local_dashboard" }),
    });
    const delivered = body.delivery && body.delivery.real_switch;
    state.notice = delivered
      ? `Decision recorded and delivered through Switch: ${body.approval.status}.`
      : `Decision recorded locally: ${body.approval.status}. This was not a Switch delivery.`;
    await refresh();
  } catch (error) {
    state.error = error.message || String(error);
    state.busy = "";
    render();
  } finally {
    state.busy = "";
    if (state.overview) render();
  }
}

async function execute(item) {
  state.busy = item.id;
  state.error = "";
  render();
  try {
    const body = await fetchJson(`/api/incidents/${item.incident_id}/approvals/${item.id}/execute`, { method: "POST" });
    const result = body.verification_result || (body.approval && body.approval.verification_result) || body.status || "completed";
    state.notice = `Server finished execution. Verification result: ${result}.`;
    await refresh();
  } catch (error) {
    state.error = error.message || String(error);
    state.busy = "";
    render();
  } finally {
    state.busy = "";
    if (state.overview) render();
  }
}

async function sendSimulation() {
  const body = state.draft.trim();
  if (!body) {
    state.error = "Enter a message before sending.";
    render();
    return;
  }
  state.busy = "sim";
  state.error = "";
  render();
  try {
    const payload = await fetchJson("/api/switch/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ room_id: "room-sim", body, sender_name: state.approver || "Local Operator" }),
    });
    state.notice = payload.real_switch_proven ? "Switch accepted the message." : "Local simulation only. Switch was not used.";
    const incident = payload.incident && payload.incident.id;
    await refresh();
    if (incident) go(`/incidents/${incident}`);
    else if (payload.shadow_incident_id) go(`/incidents/${payload.shadow_incident_id}`);
  } catch (error) {
    state.error = error.message || String(error);
    state.busy = "";
    render();
  } finally {
    state.busy = "";
    if (state.overview) render();
  }
}

async function checkIntegrity() {
  state.busy = "audit";
  render();
  try {
    const body = await fetchJson("/api/audit/verify");
    state.notice = `${body.verified ? "Ledger verified." : "Ledger failed."} ${body.details} ${body.evidence_details}`;
    await refresh();
  } catch (error) {
    state.error = error.message || String(error);
    state.busy = "";
    render();
  } finally {
    state.busy = "";
    if (state.overview) render();
  }
}

window.addEventListener("hashchange", () => {
  state.error = "";
  state.confirm = "";
  render();
});
refresh();
