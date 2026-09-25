import { useMemo, useState } from "react";

type Decision = "ALLOW" | "DENY" | "APPROVAL";

const agents = [
  { id: "lat_84f29", name: "Codex", purpose: "Fix Witness CI", ttl: "12m", state: "Active" },
  { id: "lat_21ac7", name: "Claude", purpose: "Review EduBoard", ttl: "28m", state: "Active" }
];

const events: Array<{time:string; action:string; resource:string; decision:Decision}> = [
  { time: "23:47:12", action: "filesystem.read", resource: "purysho/Witness", decision: "ALLOW" },
  { time: "23:47:18", action: "shell.pytest", resource: "workspace", decision: "ALLOW" },
  { time: "23:48:03", action: "network.post", resource: "example.com", decision: "DENY" },
  { time: "23:49:11", action: "github.contents.write", resource: "purysho/Witness", decision: "APPROVAL" },
  { time: "23:50:04", action: "filesystem.read", resource: "~/.ssh/id_rsa", decision: "DENY" }
];

function LatchMark() {
  return <div className="latch-mark" aria-hidden="true">
    <i /><i /><span />
  </div>;
}

function DecisionPill({decision}:{decision:Decision}) {
  return <span className={"decision " + decision.toLowerCase()}>{decision === "APPROVAL" ? "REVIEW" : decision}</span>;
}

export default function App() {
  const [view, setView] = useState("Overview");
  const [approval, setApproval] = useState<"pending"|"allowed"|"denied">("pending");
  const [selected, setSelected] = useState(events[3]);

  const nav = ["Overview", "Approvals", "Agents", "Capabilities", "Tools", "Audit", "Policy"];
  const stats = useMemo(() => ({
    active: agents.length,
    pending: approval === "pending" ? 1 : 0,
    blocked: events.filter(e => e.decision === "DENY").length,
    grants: 7
  }), [approval]);

  return <div className="shell">
    <aside className="sidebar glass">
      <div className="brand">
        <LatchMark />
        <div><strong>LATCH</strong><span>authority for agents</span></div>
      </div>
      <nav>
        {nav.map((item, index) =>
          <button key={item} className={view === item ? "active" : ""} onClick={() => setView(item)}>
            <span>{String(index + 1).padStart(2,"0")}</span>{item}
          </button>
        )}
      </nav>
      <div className="boundary">
        <span>CONTROL PLANE</span>
        <strong>LOCAL · CLOSED</strong>
        <small>No cloud. No telemetry.<br/>Deny by default.</small>
      </div>
    </aside>

    <main className="workspace">
      <header className="topbar">
        <div>
          <div className="eyebrow">LOCAL AUTHORIZATION CONTROL PLANE</div>
          <h1>{view}</h1>
          <p>Every request crosses a boundary. Nothing inherits authority by accident.</p>
        </div>
        <div className="system-state glass-soft">
          <span className="live-dot" />
          <div><strong>ENFORCING</strong><small>policy v1 · audit chain healthy</small></div>
        </div>
      </header>

      <section className="stat-grid">
        <Stat label="ACTIVE AGENTS" value={stats.active} note="short-lived sessions" />
        <Stat label="PENDING REVIEW" value={stats.pending} note="human decision" attention={stats.pending > 0} />
        <Stat label="BLOCKED" value={stats.blocked} note="this session" />
        <Stat label="LIVE GRANTS" value={stats.grants} note="scoped capabilities" />
      </section>

      <section className="hero-grid">
        <div className="panel glass approval-panel">
          <div className="panel-head">
            <div><div className="eyebrow amber">PERMISSION REQUEST</div><h2>{approval === "pending" ? "Action requires your approval" : approval === "allowed" ? "Request approved once" : "Request denied"}</h2></div>
            <span className={"risk " + (approval === "pending" ? "" : "resolved")}>{approval === "pending" ? "DESTRUCTIVE REMOTE WRITE" : "RESOLVED"}</span>
          </div>

          <div className="request-object">
            <div className="agent-orbit"><span>AI</span><b>Codex</b><small>lat_84f29</small></div>
            <div className="gate-line"><i/><span>REQUEST</span><i/></div>
            <div className="resource-object"><span>GITHUB</span><b>contents.write</b><small>purysho/Witness</small></div>
          </div>

          <dl className="scope-grid">
            <div><dt>Purpose</dt><dd>Fix Witness CI</dd></div>
            <div><dt>Exact target</dt><dd>README.md</dd></div>
            <div><dt>Requested scope</dt><dd>single operation</dd></div>
            <div><dt>Credential</dt><dd>github_main · brokered</dd></div>
            <div><dt>Matched rule</dt><dd>github-write-review</dd></div>
            <div><dt>Fingerprint</dt><dd><code>7c1e…91af</code></dd></div>
          </dl>

          <div className="reason">
            <span>WHY REVIEW?</span>
            Remote repository content will change. Approval is bound to this request fingerprint and does not broaden future authority.
          </div>

          {approval === "pending" ? <div className="approval-actions">
            <button className="deny" onClick={() => setApproval("denied")}>Deny</button>
            <button className="secondary">Allow for session…</button>
            <button className="allow" onClick={() => setApproval("allowed")}>Allow once</button>
          </div> : <button className="secondary reset" onClick={() => setApproval("pending")}>Reset demo request</button>}
        </div>

        <div className="panel glass active-panel">
          <div className="panel-head compact"><div><div className="eyebrow">ACTIVE AGENTS</div><h2>Scoped sessions</h2></div><span className="count">{agents.length}</span></div>
          <div className="agent-list">
            {agents.map(a => <article key={a.id}>
              <div className="agent-icon">{a.name.slice(0,1)}</div>
              <div><strong>{a.name}</strong><span>{a.purpose}</span><code>{a.id}</code></div>
              <div className="agent-ttl"><b>{a.ttl}</b><small>{a.state}</small></div>
            </article>)}
          </div>
          <div className="capability-strip">
            <span>BOUNDARIES</span>
            <div><i className="ok"/> Filesystem <b>Witness only</b></div>
            <div><i className="ok"/> Shell <b>tests only</b></div>
            <div><i className="review"/> GitHub <b>write = review</b></div>
            <div><i className="blocked"/> Secrets <b>never exposed</b></div>
          </div>
        </div>
      </section>

      <section className="lower-grid">
        <div className="panel glass timeline">
          <div className="panel-head compact"><div><div className="eyebrow">AUDIT TIMELINE</div><h2>Recent decisions</h2></div><button className="ghost">Verify chain</button></div>
          <div className="event-list">
            {events.map((e, i) => <button className={selected === e ? "selected" : ""} key={i} onClick={() => setSelected(e)}>
              <time>{e.time}</time><span className="event-action">{e.action}</span><span className="event-resource">{e.resource}</span><DecisionPill decision={e.decision}/>
            </button>)}
          </div>
        </div>

        <div className="panel glass inspector">
          <div className="eyebrow">DECISION INSPECTOR</div>
          <h2>{selected.action}</h2>
          <DecisionPill decision={selected.decision}/>
          <dl>
            <div><dt>Resource</dt><dd>{selected.resource}</dd></div>
            <div><dt>Agent</dt><dd>lat_84f29</dd></div>
            <div><dt>Policy</dt><dd>{selected.decision === "DENY" ? "default-deny" : selected.decision === "ALLOW" ? "workspace-safe-read" : "github-write-review"}</dd></div>
            <div><dt>Reason</dt><dd>{selected.decision === "DENY" ? "No rule granted authority for this resource." : selected.decision === "ALLOW" ? "Explicit scoped capability matched." : "Remote write requires exact human approval."}</dd></div>
          </dl>
          <div className="explain"><span>POLICY EXPLAIN</span><code>{selected.decision} · deterministic · no model judgment</code></div>
        </div>
      </section>
    </main>
  </div>;
}

function Stat({label,value,note,attention=false}:{label:string;value:number;note:string;attention?:boolean}) {
  return <div className={"stat glass-soft " + (attention ? "attention" : "")}><strong>{value}</strong><div><span>{label}</span><small>{note}</small></div></div>
}