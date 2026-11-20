"use strict";

const byId = (id) => document.getElementById(id);
const label = (value) => String(value ?? "—").replaceAll("_", " ");
const last = (rows, id) => rows.filter((row) => row.proposal_id === id).at(-1);
const state = { current: null, graphKey: "", pending: false, notice: "", error: false };
let cy;
let renderEventsKey = "";
let commandGeneration = 0;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}

async function api(path, body) {
  const options = body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
  const response = await fetch("/api/v1/" + path, options);
  const value = await response.json();
  if (!response.ok) throw new Error(value.error);
  return value;
}

function graph(snapshot) {
  const principals = [...snapshot.identities, ...snapshot.sessions];
  const key = JSON.stringify([snapshot.incident_id, snapshot.assets, principals, snapshot.dependencies]);
  if (key === state.graphKey) return;
  state.graphKey = key;
  byId("graph-selection").textContent = "Select a resource to inspect it.";
  const baseline = new Map([...snapshot.scenario.assets, ...snapshot.scenario.identities, ...snapshot.scenario.sessions]
    .map((item) => [item.id, item.state ?? item.status]));
  const elements = [...snapshot.assets, ...principals].map((item) => {
    const currentState = item.state ?? item.status;
    return {
      data: { ...item, label: item.name || item.id, currentState },
      classes: [item.shared ? "shared" : "", item.status ? "identity" : "",
        currentState !== baseline.get(item.id) ? "changed" : ""].join(" "),
    };
  });
  for (const session of snapshot.sessions) {
    elements.push({
      data: { id: "session-link-" + session.id, source: session.id, target: session.identity_id, type: "uses_identity" },
      classes: "session-link",
    });
  }
  const initialEdges = new Set(snapshot.scenario.dependencies.map((edge) => JSON.stringify(edge)));
  for (const [index, dependency] of snapshot.dependencies.entries()) {
    elements.push({
      data: { ...dependency, id: "edge-" + index },
      classes: initialEdges.has(JSON.stringify(dependency)) ? "" : "changed",
    });
  }
  if (cy) cy.destroy();
  cy = cytoscape({
    container: byId("graph"),
    elements,
    layout: { name: "breadthfirst", directed: true, padding: 34, spacingFactor: 1.5 },
    minZoom: 0.35,
    maxZoom: 2,
    style: [
      { selector: "node", style: {
        label: "data(label)", color: "#eaf0f7", "font-size": 12, "font-weight": 600,
        "background-color": "#355e7d", "border-color": "#789abd", "border-width": 2,
        shape: "round-rectangle", width: 190, height: 50, "text-halign": "center",
        "text-valign": "center", "text-wrap": "wrap", "text-max-width": 166,
      } },
      { selector: "node.shared", style: { "background-color": "#24554e", "border-color": "#70d9bb" } },
      { selector: "node.identity", style: { "background-color": "#4c3d73", "border-color": "#ae9be4" } },
      { selector: "node.changed", style: { "background-color": "#5a4433", "border-color": "#f2c080" } },
      { selector: "node:selected", style: { "border-width": 4 } },
      { selector: "edge", style: {
        width: 2, "line-color": "#6d8498", "target-arrow-color": "#8eacbe",
        "target-arrow-shape": "triangle", "curve-style": "bezier",
      } },
      { selector: "edge.session-link", style: { "line-style": "dashed" } },
      { selector: "edge.changed", style: { "line-color": "#f2c080", "target-arrow-color": "#f2c080" } },
    ],
  });
  cy.on("tap", "node", (event) => {
    const item = event.target.data();
    byId("graph-selection").textContent =
      [item.id, item.tenant_id, item.criticality, item.currentState].filter(Boolean).join(" · ");
  });
  cy.on("tap", "edge", (event) => {
    const { source, target, type } = event.target.data();
    byId("graph-selection").textContent = [source, label(type), target].join(" · ");
  });
}

function timeline(events) {
  const key = JSON.stringify(events);
  if (key === renderEventsKey) return;
  renderEventsKey = key;
  const list = byId("events");
  const open = new Set([...list.querySelectorAll("li:has(details[open])")].map((item) => item.dataset.event));
  list.replaceChildren(...events.slice().reverse().map((event) => {
    const item = node("li");
    item.dataset.event = event.incident_id + "/" + event.sequence;
    item.append(node("strong", String(event.sequence).padStart(2, "0")));
    item.append(node("span", label(event.event_type)));
    item.append(node("p", [event.actor_id, event.target_id, label(event.outcome)].join(" · ")));
    if (event.payload && Object.keys(event.payload).length) {
      const info = node("details");
      info.open = open.has(item.dataset.event);
      info.append(node("summary", "Event details"), node("pre", JSON.stringify(event.payload, null, 2)));
      item.append(info);
    }
    return item;
  }));
}

function actionButton(title, action, body) {
  const button = node("button", title);
  button.type = "button";
  button.disabled = state.pending || state.current.job?.state === "running";
  button.addEventListener("click", () => run(action, typeof body === "function" ? body() : body));
  return button;
}

function proposalCard(proposal, manifest, snapshot) {
  const id = proposal.id;
  const decision = last(manifest.decisions, id);
  const verification = last(manifest.verifications, id);
  const approval = last(manifest.approvals, id);
  const caps = manifest.capabilities.filter((cap) => cap.proposal_id === id);
  const issued = caps.filter((cap) => cap.status === "issued").at(-1);
  const used = caps.filter((cap) => cap.status === "consumed").at(-1);
  const card = node("article", undefined, "proposal");
  const heading = node("div", undefined, "proposal-head");
  heading.append(node("h3", `${proposal.action_type} · ${proposal.target_id}`));
  heading.append(node("span", label(decision?.result || "PENDING"), "pill" +
    (/^(PENDING|HOLD|REQUIRE_APPROVAL|DENY)$/.test(decision?.result || "PENDING") ? " pending" : "")));
  card.append(heading, node("p", proposal.rationale || "No rationale supplied."));
  if (decision) {
    card.append(node("p", decision.reason_codes.map(label).join(" · ")));
    const impact = decision.impact;
    if (impact) {
      const details = node("details");
      details.append(node("summary", `${impact.tenants.length} affected tenant(s) · ${impact.affected.length} affected resource(s)` +
        (impact.critical_shared ? " · Critical shared dependency" : "")));
      details.append(node("p", "Tenants · " + (impact.tenants.join(", ") || "None")));
      details.append(node("p", "Resources · " + (impact.affected.join(", ") || "None")));
      card.append(details);
    }
  }
  if (proposal.expected_effect) card.append(node("p", "Expected effect · " + proposal.expected_effect));
  if (proposal.evidence_refs.length) card.append(node("p", "Evidence · " + proposal.evidence_refs.join(", ")));
  if (approval) card.append(node("p", `Human review · ${approval.approver_id} · ${approval.decision}`));
  if (verification) {
    card.append(node("p", "Verification · " + label(verification.result)));
    const details = node("details");
    details.append(node("summary", "Verification details"), node("pre", JSON.stringify(verification, null, 2)));
    card.append(details);
  }
  const actions = node("div", undefined, "buttons");
  actions.append(actionButton(decision ? "Re-evaluate" : "Evaluate proposal", "evaluate", { proposal_id: id }));
  if (decision?.result === "REQUIRE_APPROVAL") {
    const approvers = snapshot.identities.filter((identity) =>
      identity.type === "human" && identity.status === "active" && identity.tenant_id === proposal.tenant_id &&
      identity.roles?.includes("incident_owner"));
    if (approvers.length) {
      const actor = node("select");
      actor.id = "reviewer-" + id;
      const actorLabel = node("label", "Incident owner");
      actorLabel.htmlFor = actor.id;
      for (const approver of approvers) {
        const option = node("option", approver.name || approver.id);
        option.value = approver.id;
        actor.append(option);
      }
      card.append(actorLabel, actor);
      actions.append(actionButton("Approve", "approve", () => ({ proposal_id: id, actor: actor.value, accept: true })));
      actions.append(actionButton("Reject", "approve", () => ({ proposal_id: id, actor: actor.value, accept: false })));
    } else {
      card.append(node("p", "No active incident owner is available."));
    }
  }
  if (issued) actions.append(actionButton("Execute scoped action", "execute", { capability_id: issued.id }));
  if (used) actions.append(actionButton("Retry used capability", "execute", { capability_id: used.id }));
  card.append(actions);
  return card;
}

function render() {
  if (!state.current) return;
  const { snapshot, manifest, job } = state.current;
  const scenario = snapshot.scenario;
  const working = job?.state === "running";
  const investigating = working && job.kind === "investigate";
  byId("scenario").value = scenario.id;
  byId("scenario").disabled = state.pending || investigating;
  byId("mode").disabled = state.pending || working;
  byId("description").textContent = scenario.description || scenario.name;
  byId("incident").textContent = snapshot.incident_id;
  byId("incident-state").textContent = label(snapshot.state);
  byId("revision").textContent = snapshot.revision;
  byId("proposal-count").textContent = manifest.proposals.length;
  const allEventsPlayed = snapshot.cursor >= scenario.events.length;
  for (const button of document.querySelectorAll("[data-action]")) {
    const action = button.dataset.action;
    if (action === "pause") {
      button.hidden = !working || investigating;
      button.disabled = state.pending || button.hidden;
      continue;
    }
    button.disabled = state.pending || (working && (action !== "reset" || investigating)) ||
      (allEventsPlayed && (action === "step" || action === "replay")) ||
      (action === "alternative" && !scenario.proposals.some((proposal) => proposal.phase === "alternative") && byId("mode").value === "DETERMINISTIC_REPLAY");
  }
  const notice = byId("notice");
  const jobNotice = working ? (investigating ? "Investigation in progress…" : "Replaying scenario events…") :
    job?.error || job?.result?.summary || (job?.state === "paused" ? "Replay paused." : "");
  notice.textContent = state.notice || jobNotice;
  notice.hidden = !notice.textContent;
  notice.classList.toggle("error", state.error || job?.state === "failed");
  graph(snapshot);
  timeline(snapshot.events);
  byId("proposals").replaceChildren(...(manifest.proposals.length ?
    manifest.proposals.slice().reverse().map((proposal) => proposalCard(proposal, manifest, snapshot)) :
    [node("p", "Run an investigation to see proposed actions.", "empty")]));
  byId("manifest").textContent = JSON.stringify(manifest, null, 2);
}

let timer;
function schedule() {
  clearTimeout(timer);
  if (state.current?.job?.state === "running") {
    const generation = commandGeneration;
    timer = setTimeout(async () => {
      if (state.pending) return schedule();
      try {
        const current = await api("state");
        if (generation !== commandGeneration) return;
        state.current = current;
      } catch (error) {
        if (generation !== commandGeneration) return;
        state.notice = error.message;
        state.error = true;
      }
      render();
      schedule();
    }, 350);
  }
}

async function run(action, body = {}) {
  if (state.pending) return;
  clearTimeout(timer);
  commandGeneration++;
  state.notice = "";
  state.error = false;
  state.pending = true;
  render();
  try {
    state.current = await api(action, body);
    if (state.current.result?.result) {
      state.notice = "Execution result · " + label(state.current.result.result);
    }
  } catch (error) {
    state.notice = error.message;
    state.error = true;
  } finally {
    state.pending = false;
    render();
    schedule();
  }
}

async function init() {
  const [catalog, current] = await Promise.all([api("scenarios"), api("state")]);
  for (const scenario of catalog) {
    const option = node("option", scenario.title);
    option.value = scenario.id;
    byId("scenario").append(option);
  }
  state.current = current;
  byId("scenario").addEventListener("change", (event) => run("load", { scenario_id: event.target.value }));
  byId("mode").addEventListener("change", render);
  byId("fit").addEventListener("click", () => cy?.fit(undefined, 34));
  new ResizeObserver(() => cy?.resize().fit(undefined, 34)).observe(byId("graph"));
  for (const button of document.querySelectorAll("[data-action]")) {
    button.addEventListener("click", () => {
      const action = button.dataset.action;
      if (action === "investigate" || action === "alternative") {
        run("investigate", { mode: byId("mode").value, alternative: action === "alternative" });
      } else {
        run(action);
      }
    });
  }
  render();
  schedule();
}

init().catch((error) => {
  const notice = byId("notice");
  notice.hidden = false;
  notice.classList.add("error");
  notice.textContent = error.message;
});
