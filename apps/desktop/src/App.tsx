import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type Decision = "ALLOW" | "DENY" | "APPROVAL";
type View = "Overview" | "Approvals" | "Agents" | "Capabilities" | "Tools" | "Audit" | "Policy";
type BackendStatus = {
  version: string;
  runtime: string;
  telemetry: boolean;
  externalListeners: boolean;
};

const agents = [
  { id: "lat_84f29", name: "Codex", purpose: "Repair workspace tests", ttl: "12m", state: "Active" },
  { id: "lat_21ac7", name: "Claude", purpose: "Review documentation", ttl: "28m", state: "Active" }
];

const events: Array<{time:string; action:string; resource:string; decision:Decision}> = [
  { time: "23:47:12", action: "filesystem.read", resource: "purysho/Latch", decision: "ALLOW" },
  { time: "23:47:18", action: "shell.execute", resource: "workspace/tests", decision: "ALLOW" },
  { time: "23:48:03", action: "mcp.tool.call", resource: "unknown-provider/tool", decision: "DENY" },
  { time: "23:49:11", action: "github.contents.write", resource: "purysho/Latch", decision: "APPROVAL" },
  { time: "23:50:04", action: "filesystem.read", resource: "~/.ssh/id_rsa", decision: "DENY" }
];

const surfaceCopy: Record<Exclude<View, "Overview">, {
  eyebrow: string;
  title: string;
  description: string;
  facts: Array<[string, string, Decision | "INFO"]>;
}> = {
  Approvals: {
    eyebrow: "HUMAN AUTHORITY",
    title: "Approval queue",
    description: "Exact requests stay separate from reusable grants. Destructive GitHub actions require one-time approval.",
    facts: [
      ["github.contents.write", "remote mutation · exact fingerprint", "APPROVAL"],
      ["github.pull.merge", "destructive · one-time only", "APPROVAL"],
      ["mcp.tool.call", "descriptor changed after approval", "DENY"]
    ]
  },
  Agents: {
    eyebrow: "SESSION BOUNDARIES",
    title: "Active sessions",
    description: "Sessions are short-lived, purpose-bound identities. Capability never implies authority.",
    facts: [
      ["lat_84f29", "Codex · repair workspace tests", "ALLOW"],
      ["lat_21ac7", "Claude · review documentation", "ALLOW"],
      ["expired sessions", "execution permits fail closed", "INFO"]
    ]
  },
  Capabilities: {
    eyebrow: "LEAST PRIVILEGE",
    title: "Capability grants",
    description: "Filesystem, shell, MCP, secrets and GitHub each revalidate their own boundary at execution time.",
    facts: [
      ["filesystem", "canonical path + protected-path checks", "ALLOW"],
      ["secrets", "reference + consumer + version", "ALLOW"],
      ["GitHub mutation", "human approval required", "APPROVAL"]
    ]
  },
  Tools: {
    eyebrow: "EXECUTION ADAPTERS",
    title: "Tool boundary",
    description: "Every external action passes through a typed adapter instead of inheriting raw tool access.",
    facts: [
      ["MCP proxy", "schema + descriptor identity pinned", "ALLOW"],
      ["GitHub REST", "credential brokered at call time", "APPROVAL"],
      ["unknown tool drift", "stale trust is rejected", "DENY"]
    ]
  },
  Audit: {
    eyebrow: "TAMPER EVIDENCE",
    title: "Audit chain",
    description: "Material decisions and executions append to an immutable SQLite ledger linked by SHA-256.",
    facts: [
      ["request → decision", "fingerprint checked before append", "ALLOW"],
      ["secret use", "credential reference only; no material", "INFO"],
      ["ledger mutation", "UPDATE / DELETE blocked by trigger", "DENY"]
    ]
  },
  Policy: {
    eyebrow: "DETERMINISTIC POLICY",
    title: "Policy boundary",
    description: "Rules are data, model output is untrusted intent, and unmatched authority defaults to deny.",
    facts: [
      ["explicit deny", "highest precedence", "DENY"],
      ["human review", "stronger than allow for scoped actions", "APPROVAL"],
      ["no matching rule", "default deny", "DENY"]
    ]
  }
};

function LatchMark() {
  return <div className="latch-mark" aria-hidden="true"><i /><i /><span /></div>;
}

function DecisionPill({decision}:{decision:Decision}) {
  return <span className={"decision " + decision.toLowerCase()}>{decision === "APPROVAL" ? "REVIEW" : decision}</span>;
}

function PreviewNotice() {
  return <div className="preview-notice" role="note">
    <span>UI PREVIEW</span>
    <p>This desktop surface uses sample activity. Preview controls do not issue real authority; enforcement remains in the Rust crates and their tests.</p>
  </div>;
}

export default function App() {
  const [view, setView] = useState<View>("Overview");
  const [approval, setApproval] = useState<"pending"|"allowed"|"denied">("pending");
  const [selected, setSelected] = useState(events[3]);
  const [backend, setBackend] = useState<BackendStatus | null>(null);

  useEffect(() => {
    let active = true;
    invoke<BackendStatus>("control_plane_status")
      .then(status => { if (active) setBackend(status); })
      .catch(() => { if (active) setBackend(null); });
    return () => { active = false; };
  }, []);

  const nav: View[] = ["Overview", "Approvals", "Agents", "Capabilities", "Tools", "Audit", "Policy"];
  const stats = useMemo(() => ({
    active: agents.length,
    pending: approval === "pending" ? 1 : 0,
    blocked: events.filter(e => e.decision === "DENY").length,
    grants: 4
  }), [approval]);

  return <div className="shell">
    <aside className="sidebar glass">
      <div className="brand">
        <LatchMark />
        <div><strong>LATCH</strong><span>authority for agents</span></div>
      </div>
      <nav aria-label="Latch sections">
        {nav.map((item, index) =>
          <button key={item} className={view === item ? "active" : ""} onClick={() => setView(item)} aria-current={view === item ? "page" : undefined}>
            <span>{String(index + 1).padStart(2,"0")}</span>{item}
          </button>
        )}
      </nav>
      <div className="boundary">
        <span>CONTROL PLANE</span>
        <strong>{backend ? "LOCAL · CORE READY" : "LOCAL · UI PREVIEW"}</strong>
        <small>No cloud control plane.<br/>No telemetry by default.</small>
      </div>
    </aside>

    <main className="workspace">
      <header className="topbar">
        <div>
          <div className="eyebrow">LOCAL AUTHORIZATION CONTROL PLANE</div>
          <h1>{view}</h1>
          <p>Every request crosses a boundary. Nothing inherits authority by accident.</p>
        </div>
        <div className="system-state glass-soft" aria-live="polite">
          <span className={"live-dot " + (backend ? "" : "preview")} />
          <div>
            <strong>{backend ? "LOCAL CORE READY" : "UI PREVIEW"}</strong>
            <small>{backend ? `v${backend.version} · telemetry ${backend.telemetry ? "on" : "off"}` : "browser surface · sample activity"}</small>
          </div>
        </div>
      </header>

      <PreviewNotice />

      {view === "Overview"
        ? <Overview
            approval={approval}
            setApproval={setApproval}
            selected={selected}
            setSelected={setSelected}
            stats={stats}
          />
        : <SurfaceView view={view} />}
    </main>
  </div>;
}

function Overview({
  approval,
  setApproval,
  selected,
  setSelected,
  stats
}:{
  approval:"pending"|"allowed"|"denied";
  setApproval:(value:"pending"|"allowed"|"denied")=>void;
  selected:(typeof events)[number];
  setSelected:(value:(typeof events)[number])=>void;
  stats:{active:number;pending:number;blocked:number;grants:number};
}) {
  return <>
    <section className="stat-grid" aria-label="Sample control plane summary">
      <Stat label="ACTIVE AGENTS" value={stats.active} note="sample sessions" />
      <Stat label="PENDING REVIEW" value={stats.pending} note="sample request" attention={stats.pending > 0} />
      <Stat label="BLOCKED" value={stats.blocked} note="sample activity" />
      <Stat label="LIVE GRANTS" value={stats.grants} note="sample capabilities" />
    </section>

    <section className="hero-grid">
      <div className="panel glass approval-panel">
        <div className="panel-head">
          <div><div className="eyebrow amber">SAMPLE PERMISSION REQUEST</div><h2>{approval === "pending" ? "Action requires human approval" : approval === "allowed" ? "Preview: approved once" : "Preview: request denied"}</h2></div>
          <span className={"risk " + (approval === "pending" ? "" : "resolved")}>{approval === "pending" ? "REMOTE WRITE" : "PREVIEW RESOLVED"}</span>
        </div>

        <div className="request-object">
          <div className="agent-orbit"><span>AGENT</span><b>Codex</b><small>lat_84f29</small></div>
          <div className="gate-line"><i/><span>REQUEST</span><i/></div>
          <div className="resource-object"><span>GITHUB</span><b>contents.write</b><small>purysho/Latch</small></div>
        </div>

        <dl className="scope-grid">
          <div><dt>Purpose</dt><dd>Repair workspace tests</dd></div>
          <div><dt>Exact target</dt><dd>README.md</dd></div>
          <div><dt>Requested scope</dt><dd>single operation</dd></div>
          <div><dt>Credential</dt><dd>github_main · brokered</dd></div>
          <div><dt>Matched rule</dt><dd>github-write-review</dd></div>
          <div><dt>Fingerprint</dt><dd><code>7c1e…91af</code></dd></div>
        </dl>

        <div className="reason">
          <span>WHY REVIEW?</span>
          Remote repository content will change. A real approval is bound to the exact request fingerprint and does not broaden future authority.
        </div>

        {approval === "pending" ? <div className="approval-actions" aria-label="Preview approval controls">
          <button className="deny" onClick={() => setApproval("denied")}>Simulate deny</button>
          <button className="secondary" disabled title="Session-grant preview is intentionally disabled">Session grant</button>
          <button className="allow" onClick={() => setApproval("allowed")}>Simulate allow once</button>
        </div> : <button className="secondary reset" onClick={() => setApproval("pending")}>Reset preview request</button>}
      </div>

      <div className="panel glass active-panel">
        <div className="panel-head compact"><div><div className="eyebrow">SAMPLE AGENTS</div><h2>Scoped sessions</h2></div><span className="count">{agents.length}</span></div>
        <div className="agent-list">
          {agents.map(a => <article key={a.id}>
            <div className="agent-icon">{a.name.slice(0,1)}</div>
            <div><strong>{a.name}</strong><span>{a.purpose}</span><code>{a.id}</code></div>
            <div className="agent-ttl"><b>{a.ttl}</b><small>{a.state}</small></div>
          </article>)}
        </div>
        <div className="capability-strip">
          <span>BOUNDARIES</span>
          <div><i className="ok"/> Filesystem <b>Latch only</b></div>
          <div><i className="ok"/> Shell <b>tests only</b></div>
          <div><i className="review"/> GitHub <b>write = review</b></div>
          <div><i className="blocked"/> Secrets <b>material hidden</b></div>
        </div>
      </div>
    </section>

    <section className="lower-grid">
      <div className="panel glass timeline">
        <div className="panel-head compact"><div><div className="eyebrow">SAMPLE AUDIT TIMELINE</div><h2>Recent decisions</h2></div><span className="sample-chip">DEMO DATA</span></div>
        <div className="event-list">
          {events.map((e, i) => <button className={selected === e ? "selected" : ""} key={i} onClick={() => setSelected(e)}>
            <time>{e.time}</time><span className="event-action">{e.action}</span><span className="event-resource">{e.resource}</span><DecisionPill decision={e.decision}/>
          </button>)}
        </div>
      </div>

      <div className="panel glass inspector">
        <div className="eyebrow">DECISION INSPECTOR · SAMPLE</div>
        <h2>{selected.action}</h2>
        <DecisionPill decision={selected.decision}/>
        <dl>
          <div><dt>Resource</dt><dd>{selected.resource}</dd></div>
          <div><dt>Agent</dt><dd>lat_84f29</dd></div>
          <div><dt>Policy</dt><dd>{selected.decision === "DENY" ? "default-deny" : selected.decision === "ALLOW" ? "workspace-safe-read" : "github-write-review"}</dd></div>
          <div><dt>Reason</dt><dd>{selected.decision === "DENY" ? "No rule granted authority for this resource." : selected.decision === "ALLOW" ? "Explicit scoped capability matched." : "Remote mutation requires exact human approval."}</dd></div>
        </dl>
        <div className="explain"><span>POLICY EXPLAIN</span><code>{selected.decision} · deterministic · no model judgment</code></div>
      </div>
    </section>
  </>;
}

function SurfaceView({view}:{view:Exclude<View,"Overview">}) {
  const surface = surfaceCopy[view];
  return <section className="panel glass surface-panel">
    <div className="surface-head">
      <div>
        <div className="eyebrow">{surface.eyebrow}</div>
        <h2>{surface.title}</h2>
        <p>{surface.description}</p>
      </div>
      <span className="sample-chip">PREVIEW DATA</span>
    </div>
    <div className="surface-list">
      {surface.facts.map(([name, detail, decision]) =>
        <article key={name}>
          <div><strong>{name}</strong><span>{detail}</span></div>
          {decision === "INFO" ? <span className="info-pill">INFO</span> : <DecisionPill decision={decision} />}
        </article>
      )}
    </div>
    <div className="surface-boundary">
      <span>V0.1 BOUNDARY</span>
      <p>The Rust authorization, approval, adapter and audit crates are the enforcement surface. This screen is intentionally explicit when it is showing representative data rather than live authority.</p>
    </div>
  </section>;
}

function Stat({label,value,note,attention=false}:{label:string;value:number;note:string;attention?:boolean}) {
  return <div className={"stat glass-soft " + (attention ? "attention" : "")}><strong>{value}</strong><div><span>{label}</span><small>{note}</small></div></div>;
}
