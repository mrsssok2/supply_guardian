"""Software Supply Chain Guardian - Streamlit dashboard (local only, detection only)."""
import json
from pathlib import Path

import networkx as nx
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "out"
st.set_page_config(page_title="Supply Chain Guardian", layout="wide")


@st.cache_data
def _load(name, mtime, default):
    return json.loads((OUT / name).read_text()) if mtime else default


def load(name, default):
    """Cached per file *modification time*, so re-running the pipeline never serves stale data."""
    p = OUT / name
    return _load(name, p.stat().st_mtime_ns if p.exists() else 0, default)


components_ = load("components.json", [])
cves = load("cves.json", [])
findings = load("findings.json", [])
changes = load("changes.json", [])
score = load("score.json", {})
agent = load("agent.json", {})
prio = load("priority.json", {})
graph = load("graph.json", {})
RISK_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦"}

# ------------------------------------------------------------------ header
st.title("🛡️ Software Supply Chain Guardian")
st.caption("ROS 2 / TurtleBot3 robot (image gurdy2/ros:jazzy) · detection only · everything local")
if score:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Planted risks found", f"{len(score['found'])}/{score['planted_total']}")
    c2.metric("False alarms", len(score["false_alarms"]))
    c3.metric("Suspicious findings", len(findings))
    c4.metric("CVEs (Trivy)", len(cves))
    st.markdown(f"**Planted risks found: {len(score['found'])}/{score['planted_total']}, "
                f"false alarms: {len(score['false_alarms'])}**"
                + (f" · decoy flagged: {len(score['decoy_flagged'])}" if score.get("decoy_flagged") is not None else ""))
if not components_:
    st.error("No data in out/. Run ./run.sh (or guardian/discover.py then guardian/suspicious.py).")
    st.stop()

tab_in, tab_chg, tab_risk, tab_val = st.tabs(["What's inside", "What changed", "What's risky", "Validation"])

# ------------------------------------------------------------------ inside
with tab_in:
    df = pd.DataFrame(components_)
    df = df[df["kind"] != "rosdep-key-unresolved"]
    df["path"] = df["path"].apply(lambda p: " → ".join(p) if p else "(base image only, not used by TurtleBot3)")
    left, right = st.columns([1, 1])
    with left:
        st.subheader("Components per layer")
        st.bar_chart(df["layer"].value_counts())
    with right:
        st.subheader("Direct vs transitive")
        rel = pd.crosstab(df["layer"], df["relation"])
        st.dataframe(rel, width='stretch')
        st.caption("Rows = layers, columns = how a component relates to the TurtleBot3 packages.")
    st.caption("**Relations:** *workspace root* = a TurtleBot3 package itself · *direct* = depended on directly by a TurtleBot3 package · "
               "*transitive* = reached through other dependencies · *base image only* = in the image but no TurtleBot3 dependency path leads to it.")
    st.subheader("Component search")
    q1, q2, q3 = st.columns([3, 1, 1])
    text = q1.text_input("Search name / path", "")
    layers = q2.multiselect("Layer", sorted(df["layer"].unique()))
    rels = q3.multiselect("Relation", sorted(df["relation"].unique()))
    v = df
    if text:
        v = v[v["name"].str.contains(text, case=False, na=False) | v["path"].str.contains(text, case=False, na=False)]
    if layers:
        v = v[v["layer"].isin(layers)]
    if rels:
        v = v[v["relation"].isin(rels)]
    st.caption(f"{len(v)} components")
    st.dataframe(v[["name", "version", "layer", "relation", "distance", "cve_count", "path"]],
                 width='stretch', height=360, hide_index=True)

    st.caption("Every component found in the image, workspace, robot.repos, Dockerfile and CI, with the shortest dependency path from a TurtleBot3 package.")
    gf = OUT / "graph_full.html"
    if gf.exists():
        st.markdown('<a href="http://127.0.0.1:8502/graph_full.html" target="_blank" style="display:inline-block;padding:8px 14px;background:#238636;color:#fff;'
                    'border-radius:6px;text-decoration:none;font-weight:600">Open full-screen graph ↗</a>', unsafe_allow_html=True)
        st.caption("Standalone page (works offline), served by run.sh on http://127.0.0.1:8502 (a plain `python3 -m http.server` on out/): precomputed left-to-right layout by dependency depth, "
                   "all ROS packages by default, toggle for apt/pip, search, click a node for its path and details. "
                   "Without run.sh, open the file directly from WSL: `explorer.exe $(wslpath -w out/graph_full.html)`")
        st.download_button("Download graph_full.html", gf.read_bytes(), file_name="graph_full.html", mime="text/html")
    st.subheader("TurtleBot3 top-level packages and their direct dependencies")
    try:
        from pyvis.network import Network
        G = nx.node_link_graph(graph, edges="edges")
        roots = [n for n, d in G.nodes(data=True) if d.get("layer") == "source" and d.get("kind") == "ros-package"
                 and d["name"].startswith("turtlebot3")]
        roots_set = set(roots)
        blast = {n: len(nx.ancestors(G, n) & roots_set) for n, d in G.nodes(data=True) if d.get("layer") in ("ros", "source")}
        RT_TAGS = {"depend", "exec_depend", "run_depend", "build_export_depend"}
        RG = nx.DiGraph()
        RG.add_nodes_from(G.nodes)
        RG.add_edges_from((u, v) for u, v, e in G.edges(data=True) if set(e.get("type", "").split(",")) & RT_TAGS)
        rblast = {n: len(nx.ancestors(RG, n) & roots_set) for n in blast}
        Y = len(roots)
        net = Network(height="560px", width="100%", directed=True, bgcolor="#0e1117", font_color="white")
        colour = {"source": "#ff7f0e", "ros": "#1f77b4", "apt": "#2ca02c", "pip": "#9467bd"}
        AMBER, RED = "#ffc107", "#e53935"
        amber = prio.get("ros_amber", {})  # ROS package -> libs its OWN binaries link (ldd) that carry runtime CVEs
        sub = set(roots)
        for r in roots:
            sub.update(s for s in G.successors(r) if G.nodes[s].get("layer") in ("source", "ros"))
        for n in sub:
            d = G.nodes[n]
            has_cve = d["name"] in amber
            br = blast.get(n, 0)
            size = 30 if n in roots else (12 + 2.5 * br if d["layer"] == "ros" else 18)
            net.add_node(n, label=d["name"], shape="dot", size=size,
                         color={"background": colour.get(d["layer"], "#888"), "border": AMBER if has_cve else colour.get(d["layer"], "#888"),
                                "highlight": {"background": colour.get(d["layer"], "#888"), "border": "#fff"}},
                         borderWidth=5 if has_cve else 1, font={"size": 20, "color": "#ffffff", "strokeWidth": 3, "strokeColor": "#0e1117"},
                         title=f"{d['name']} ({d['layer']} {d.get('version', '')})\nbuild-time blast radius: {br} of {Y} TurtleBot3 packages (all dependency types)\nruntime blast radius: {rblast.get(n, 0)} of {Y} (depend/exec_depend/build_export_depend)"
                         + ("\nruntime CVEs in libs its own binaries link: " + ", ".join(f"{k} ({v['cves']} CVEs, worst {v['worst']}) via {v['binary']}" for k, v in list(amber[d["name"]].items())[:4]) if has_cve else ""))
        for u, w in G.edges(sub):
            if u in sub and w in sub:
                net.add_edge(u, w, color="#888888")
        # planted / suspicious packages from the findings (they do not exist on main, so not in graph.json)
        for f in findings:
            if f["type"] == "unexpected_dependency" and f.get("dep_path"):
                owner, dep = f["dep_path"]
                oid = next((n for n in sub if G.nodes[n]["name"] == owner), None)
                if oid:
                    sbr = len((nx.ancestors(G, oid) | {oid}) & roots_set)
                    net.add_node(f"sus:{dep}", label=dep, shape="dot", size=24, color={"background": RED, "border": "#ffffff"}, borderWidth=3,
                                 font={"size": 20, "color": "#ffffff", "strokeWidth": 3, "strokeColor": "#0e1117"},
                                 title=f"{dep}\n{f['risk']} - {f['type']} ({f['file']}:{f['line']})\nbuild-time blast radius: {sbr} of {Y} TurtleBot3 packages")
                    net.add_edge(oid, f"sus:{dep}", color=RED, width=3)
        net.set_options(json.dumps({
            "physics": {"enabled": True, "solver": "forceAtlas2Based",
                        "forceAtlas2Based": {"gravitationalConstant": -120, "springLength": 180, "springConstant": 0.05, "avoidOverlap": 1},
                        "stabilization": {"enabled": True, "iterations": 200, "fit": True}},
            "interaction": {"dragNodes": True, "hover": True}, "nodes": {"font": {"size": 20}}}))
        html = net.generate_html(notebook=False).replace(
            "return network;",
            "network.once('stabilizationIterationsDone', function(){ network.setOptions({physics:{enabled:false}}); network.fit(); });\n return network;")
        components.html(html, height=580)
        st.caption("orange = TurtleBot3 workspace, blue = ROS packages in the image (size = build-time blast radius), red = suspicious/planted, "
                   "amber border = runtime CVEs in a library that the package's OWN executables/libraries link DIRECTLY (readelf NEEDED entries, not the transitive ldd chain). "
                   "Ubiquitous base libraries (libc6, libstdc++6, libgcc-s1, libpython3.12*) are ignored for the amber ring (their CVEs stay in the CVE list and funnel). "
                   "Layout is frozen after stabilisation; drag nodes to rearrange.")
        hc1, hc2 = st.columns(2)
        for col, title, br_map in ((hc1, "Top 5 hubs — build-time blast radius", blast), (hc2, "Top 5 hubs — runtime blast radius", rblast)):
            hubs = sorted(((br_map[n], len(nx.ancestors(G, n)), d["name"]) for n, d in G.nodes(data=True) if d.get("layer") == "ros"), reverse=True)[:5]
            with col:
                st.markdown(f"**{title}**")
                for k, _, name in hubs:
                    st.markdown(f"- `{name}` — if this package were compromised, **{k} of {Y}** TurtleBot3 packages would be affected")
        st.caption(f"Build-time = all dependency types; runtime = depend / exec_depend / build_export_depend only. Y = the {Y} TurtleBot3 workspace packages. "
                   "Ties are broken by total dependents in the graph. Build-tool compromise is how the SolarWinds and XZ Utils attacks worked, so build-time hubs matter.")
    except Exception as e:  # graph is a nicety, never block the demo
        st.info(f"Graph unavailable: {e}")

# ------------------------------------------------------------------ changed
with tab_chg:
    st.subheader("main → planted")
    if not changes:
        st.info("No changes.json - run guardian/suspicious.py")
    else:
        fmt = lambda x: x.strip() if isinstance(x, str) else "∅"
        owner = {}
        for f in findings:
            owner.setdefault((f["file"], f["line"]), f)
            for h in f.get("hits") or []:
                owner.setdefault((f["file"], h[0]), f)
        rows = []
        for c in changes:
            f = owner.get((c["file"], c["line"]))
            rows.append({"finding": f["id"] if f else "", "type": f["type"] if f else "", "risk": f["risk"] if f else "",
                         "file": c["file"], "line": c["line"], "status": c["status"],
                         "old → new": f"{fmt(c['old'])}  →  {fmt(c['new'])}", "_r": RISK_RANK[f["risk"]] if f else 9})
        cd = pd.DataFrame(rows).sort_values(["_r", "finding", "file", "line"])
        only = st.checkbox("Only flagged lines (those that triggered a finding)", True)
        files = sorted(cd["file"].unique())
        sel = st.multiselect("File", files)
        v = cd[cd["file"].isin(sel)] if sel else cd
        if only:
            v = v[v["finding"] != ""]
        v = v.assign(risk=v["risk"].map(lambda r: f"{ICON.get(r, '')} {r}" if r else ""))
        st.caption(f"{len(changes)} changed lines in {len(files)} files · {len(v)} shown · grouped by finding, most severe first")
        st.dataframe(v[["finding", "type", "risk", "file", "line", "status", "old → new"]], width='stretch',
                     hide_index=True, height=480)
        st.caption("Line-level diff of branch `planted` against `main`; lines that triggered a finding are listed first with the finding id, type and risk.")

# ------------------------------------------------------------------ risky
with tab_risk:
    if prio:
        fn = prio["funnel"]
        st.subheader("Recommended actions")
        plan = prio.get("plan", {})
        sm = plan.get("summary", {})
        st.markdown(f"**{fn['total']:,} unique CVEs → {fn['in_robot_tree']:,} in the robot's tree → {fn['runtime']:,} runtime → {fn['reachable']:,} reachable**"
                    + (f"  \n(CVE × library pairs: {fn['pairs']['total']:,} → {fn['pairs']['in_robot_tree']:,} → {fn['pairs']['runtime']:,} → {fn['pairs']['reachable']:,})" if fn.get("pairs") else ""))
        if sm:
            st.markdown(f"### {sm['reachable']} unique reachable CVEs → {sm['upgrade']} fixable by upgrade, {sm['removable']} removable, "
                        + (f"{sm['mitigate']} to mitigate (rviz dependency), " if sm.get("mitigate") else "")
                        + f"{sm['monitor']} to monitor")
        fc = st.columns(5)
        for col, (lab, k) in zip(fc, [("All CVEs", "total"), ("In robot's tree", "in_robot_tree"), ("Runtime", "runtime"), ("Reachable", "reachable")]):
            col.metric(lab, f"{fn.get(k, 0):,}")
        fc[4].metric("Actions", len(plan.get("actions", [])))
        st.caption("In tree = a TurtleBot3 dependency path reaches the package · runtime = not build/dev-only · reachable = linked (ldd) by "
                   f"binaries of the {len(fn['launched_packages'])} packages started by the TurtleBot3 launch files ({fn['binaries_scanned']} binaries scanned) or imported by Python nodes. "
                   "CVE counts are unique CVE IDs (one CVE can affect several libraries). Every reachable CVE is in exactly one tier: 1 upgrade (fix exists) · 2 remove/isolate (no fix, library only needed by non-runtime components; downgraded to "
                   "mitigate if the runtime dependency graph shows a robot package needs it) · 3 escalate/monitor (no fix, needed at runtime). "
                   "**These are recommendations only — fixing happens on Day 2 with human approval.**")
        TIER = {1: "Tier 1 — Upgrade", 2: "Tier 2 — Remove / isolate", 3: "Tier 3 — Monitor / escalate"}
        for t in plan.get("actions", []):
            n = t["cves_removed"] or t.get("cves_covered", 0)
            icon = {"upgrade": "⬆️", "remove": "🗑️", "mitigate": "🛡️", "monitor": "👁️"}[t["kind"]]
            label = f"{icon} {TIER[t['tier']]}{' (downgraded to mitigate)' if t['kind'] == 'mitigate' else ''}: {t['title']} · {n} reachable CVEs"
            with st.expander(label, expanded=t["tier"] == 1):
                st.markdown(f"**Expected risk reduction:** " + (f"{t['cves_removed']} unique reachable CVEs removed" if t["cves_removed"] and t["kind"] != "mitigate" else
                            (f"up to {t['cves_removed']} reachable CVEs removed once the rviz family can be dropped from the robot image" if t["kind"] == "mitigate" else
                             f"none — {t.get('cves_covered', 0)} reachable CVEs stay open and are tracked")))
                st.markdown("**Compatibility impact:** " + t["compatibility"])
                if t["packages_affected"]:
                    st.markdown(("**Robot packages affected / needing it:** " if t["tier"] != 1 else "**Robot packages that link it directly:** ")
                                + ", ".join(f"`{x}`" for x in t["packages_affected"][:30]) + (" …" if len(t["packages_affected"]) > 30 else ""))
                st.markdown("**Rollback:** " + t["rollback"])
                st.markdown("**Why:** " + " · ".join(t["reasons"]))
                if t.get("items"):
                    rows_ = [{"library": i["package"], "installed": i["installed"], "CVE-library pairs": i["cve_count"], "worst": i["worst"], "status": i["status"],
                              "needed by (robot packages)": ", ".join(i["needed_by"][:8]) + (" …" if len(i["needed_by"]) > 8 else "") or "—",
                              "evidence": i["evidence"]} for i in t["items"]]
                    st.dataframe(pd.DataFrame(rows_), width='stretch', hide_index=True)
                libs_of = t.get("cve_libs", {})
                st.markdown(f"CVE IDs ({len(t.get('cve_ids', []))} unique; ×N = number of libraries the CVE affects): "
                            + ", ".join(f"`{i}`" + (f" ×{len(libs_of.get(i, []))} ({', '.join(libs_of.get(i, []))})" if len(libs_of.get(i, [])) > 1 else "")
                            for i in t.get("cve_ids", [])))
        MAL = ("obfuscated_payload", "credential_access", "network_exfiltration", "download_and_execute", "antivirus_hit")
        mal = [f for f in findings if f["type"] in MAL]
        st.divider()
        st.subheader("Malware-like behaviour")
        av = load("av.json", {})
        st.caption("Static analysis only — nothing is executed or installed. Base64/hex strings in setup.py and scripts are decoded and the decoded text is scanned too; "
                   "the planted workspace is scanned with ClamAV. All URLs are under the reserved .invalid domain. Evidence below is verified tool output.")
        if av:
            st.markdown(f"Antivirus engine: **{av.get('engine')}** · {av.get('version', '')}" + (f" · note: {av['note']}" if av.get("note") else ""))
        if not mal:
            st.info("No malware-like behaviour found.")
        for f in mal:
            with st.expander(f"{ICON.get(f['risk'], '')} {f['type']} · `{f['file']}:{f['line']}` · {f['component']}", expanded=f["type"] == "obfuscated_payload"):
                st.markdown(f"**Why:** {f['reason']}")
                if f.get("encoded"):
                    st.markdown("Encoded line:")
                    st.code(f["encoded"], language="python")
                    st.markdown("Decoded snippet:")
                    st.code(f.get("decoded") or "", language="python")
                else:
                    st.code(f["evidence"], language="text")
                ai = agent.get(f["id"])
                if ai:
                    st.markdown("**AI inference** (not evidence): " + ai["verdict_text"])
        st.divider()
        st.subheader("All risks")
    rows = []
    def band(x):
        return "high" if x >= 9 else "medium" if x >= 4 else "low"
    for f in findings:
        rows.append({"kind": "suspicious", "id": f["id"], "tier": 0, "priority": 100.0 - RISK_RANK[f["risk"]], "level": f["risk"],
                     "exposure": "—", "reachable": "—", "trivy": "", "layer": f["layer"], "component": f["component"],
                     "why": f"{f['type']}: {f['reason']}", "ref": ("f", f["id"])})
    for i, c in enumerate(cves):
        rch = bool(c.get("reachable"))
        tier = 1 if (c.get("runtime") and rch) else 2
        why = c["priority_reasons"][1] if c.get("priority_reasons") else ""
        rows.append({"kind": "CVE", "id": c["id"], "tier": tier, "priority": c.get("score", 0.0), "level": band(c.get("score", 0.0)),
                     "exposure": c.get("exposure", "?"), "reachable": "yes" if rch else "no", "trivy": c["severity"].lower(),
                     "layer": c["layer"], "component": f"{c['package']} {c['installed']}",
                     "why": why + (f" · fix {c['fixed']}" if c["fixed"] else " · no fix listed"), "ref": ("c", i)})
    rk = pd.DataFrame(rows)
    rk["_sev"] = rk["trivy"].map(lambda r: RISK_RANK.get(r, -1))
    sort_by = st.radio("Sort by", ["Guardian priority (suspicious findings, then runtime+reachable CVEs, then the rest)", "Raw Trivy severity"], horizontal=True)
    rk = (rk.sort_values(["tier", "priority"], ascending=[True, False]) if sort_by.startswith("Guardian")
          else rk.sort_values(["_sev", "priority"], ascending=[True, False])).reset_index(drop=True)
    f1, f2, f3, f4 = st.columns([2, 2, 2, 3])
    lay = f1.multiselect("Layer", sorted(rk["layer"].unique()))
    expo = f2.multiselect("Exposure", ["runtime", "build/dev-only", "base image only"])
    lvl = f3.multiselect("Priority level", ["high", "medium", "low", "critical"], help="CVEs: Guardian band by score; findings: their risk level")
    srch = f4.text_input("Search id / component / why", "")
    v = rk
    if lay:
        v = v[v["layer"].isin(lay)]
    if expo:
        v = v[v["exposure"].isin(expo)]
    if lvl:
        v = v[v["level"].isin(lvl)]
    if srch:
        m = v[["id", "component", "why"]].astype(str).apply(lambda c: c.str.contains(srch, case=False)).any(axis=1)
        v = v[m]
    v = v.reset_index(drop=True)
    st.caption(f"{len(v)} rows ({(v['kind']=='suspicious').sum()} suspicious findings, {(v['kind']=='CVE').sum()} CVEs) — click a row for evidence and priority reasons")
    show = v.assign(level=v["level"].map(lambda r: f"{ICON.get(r, '')} {r}")).rename(
        columns={"level": "priority level", "trivy": "Trivy severity"})[
        ["priority level", "priority", "kind", "id", "exposure", "reachable", "Trivy severity", "layer", "component", "why"]]
    st.caption("Guardian priority = Trivy severity × exposure × reachability × provenance × fix availability. Suspicious findings come first, then runtime + reachable CVEs, "
               "then the rest by score. `linux-libc-dev` rows rank low: build-only kernel headers. Raw Trivy severity is shown for reference only.")
    ev = st.dataframe(show, width='stretch', hide_index=True, height=380,
                      on_select="rerun", selection_mode="single-row")
    sel = ev.selection.rows if ev and ev.selection else []
    if sel:
        kind, key = v.loc[sel[0], "ref"]
        e1, e2 = st.columns(2)
        with e1:
            st.markdown("### ✅ Verified evidence")
            st.caption("Facts taken from tools and files only")
            if kind == "f":
                f = next(x for x in findings if x["id"] == key)
                st.markdown(f"**{f['type']}** · `{f['file']}:{f['line']}` · risk **{f['risk']}**")
                st.markdown(f"Reason: {f['reason']}")
                if f.get("old") or f.get("new"):
                    st.code(f"- {f.get('old') or '∅'}\n+ {f.get('new') or '∅'}", language="diff")
                st.write(f["evidence"])
                if f.get("hits"):
                    st.code("\n".join(f"{f['file']}:{ln}  [{k}]  {t}" for ln, k, t in f["hits"]), language="text")
                if f.get("dep_path"):
                    st.markdown("Dependency path: " + " → ".join(f"`{p}`" for p in f["dep_path"]))
            else:
                c = cves[key]
                st.markdown(f"**{c['id']}** · {c['severity']} · `{c['package']}` {c['installed']} (layer: {c['layer']})")
                st.write(f"Fixed version: {c['fixed'] or 'none listed'} · status: {c['status']}")
                if "score" in c:
                    st.markdown(f"Priority score **{c['score']}** · exposure **{c['exposure']}** · reachability: {c['reachability']} · provenance: {c['provenance']}")
                    st.markdown("Score reasons: " + " · ".join(c["priority_reasons"]))
                if c.get("title"):
                    st.write(c["title"])
                st.markdown("Path from TurtleBot3: " + (" → ".join(f"`{p}`" for p in c["path"]) if c["path"] else "_not reachable in the graph_"))
                linkers = sorted(prio.get("ros_links_all", {}).get(c["package"], []))
                if linkers:
                    st.write(f"ROS packages whose own binaries link `{c['package']}` ({len(linkers)}): " + ", ".join(f"`{x}`" for x in linkers[:12]) + (" …" if len(linkers) > 12 else ""))
                if c.get("url"):
                    st.write(c["url"])
        with e2:
            st.markdown("### 🤖 AI inference")
            st.caption("Model opinion — not evidence. Generated only from the tool results at left; grounding-checked.")
            if kind == "f" and key in agent:
                a = agent[key]
                st.info(a["verdict_text"])
                st.caption(f"source: {a['source']} · verdict: {a['verdict']} · confidence: {a.get('confidence', '?')}"
                           + (f" · note: {a['note']}" if a.get("note") else ""))
                if a.get("tool_calls"):
                    with st.expander(f"Investigator tool calls ({len(a['tool_calls'])})", expanded=True):
                        for i, tc in enumerate(a["tool_calls"], 1):
                            st.markdown(f"**{i}. `{tc['tool']}`** `{json.dumps(tc['args'])}`")
                            st.code(tc["result"], language="text")
                else:
                    st.caption("No tool calls were made by the model for this finding.")
            elif kind == "f":
                st.warning("No AI verdict for this finding (only critical/high are analysed; run guardian/agent.py).")
            else:
                st.write("AI analysis covers suspicious findings only, not CVE rows.")


# ------------------------------------------------------------------ validation (Day 2 stage A: Gazebo mission main vs planted)
with tab_val:
    st.subheader("Gazebo mission validation: main vs planted")
    st.caption("One NavigateToPose goal from (-2.0, -0.5) to (1.6, -0.5) in the TurtleBot3 world with ONE box on the straight path that is NOT in the static map, "
               "so only the LiDAR can see it. Headless Gazebo + Nav2 with the image's TurtleBot3 params; PASS = goal reached AND no collision; 120 s wall-clock limit. "
               "Distances come from Gazebo ground truth (5 Hz), collisions from the box's contact sensor or a distance below the robot radius (0.105 m).")
    files = sorted(OUT.glob("mission_*.json")) or sorted((ROOT / "results" / "day2_stageA").glob("mission_*.json"))
    runs = [json.loads(f.read_text()) for f in files]
    if not runs:
        st.info("No mission results yet. Run: scripts/build_target_image.sh main main; scripts/mission_test.py --image tb3-target:main --label main_1")
    else:
        def verdict(d):
            return d.get("verdict") or ("PASS" if d["result"] == "reached" and not d["collision"] else "FAIL")
        groups = {"main": [r for r in runs if r["label"].startswith("main")], "planted": [r for r in runs if r["label"].startswith("planted")]}
        def agg(rs):
            if not rs:
                return {}
            mins = [r["min_distance_to_box_m"] for r in rs if r.get("min_distance_to_box_m") is not None]
            return {"runs": len(rs), "PASS": f"{sum(verdict(r) == 'PASS' for r in rs)}/{len(rs)}",
                    "results": ", ".join(r["result"] for r in rs), "collisions": f"{sum(bool(r['collision']) for r in rs)}/{len(rs)}",
                    "closest approach to box (m)": min(mins) if mins else None,
                    "max linear speed (m/s)": max(r["max_linear_speed_mps"] or 0 for r in rs),
                    "time to finish, sim s (per run)": ", ".join(str(r["time_sim_s"]) for r in rs),
                    "final distance to goal (m, per run)": ", ".join(str(r.get("distance_to_goal_gt_m")) for r in rs)}
        a_main, a_pl = agg(groups["main"]), agg(groups["planted"])
        c1, c2 = st.columns(2)
        c1.metric("main", a_main.get("PASS", "-") + " PASS")
        c2.metric("planted", a_pl.get("PASS", "-") + " PASS")
        keys = list(a_main or a_pl)
        st.dataframe(pd.DataFrame({"main": [a_main.get(k, "-") for k in keys], "planted": [a_pl.get(k, "-") for k in keys]}, index=keys).astype(str), width="stretch")
        rows_ = [{"run": r["label"], "image": r.get("image", ""), "verdict": verdict(r), "result": r["result"], "collision": r["collision"],
                  "min distance to box (m)": r["min_distance_to_box_m"], "max speed (m/s)": r["max_linear_speed_mps"],
                  "time wall/sim (s)": f"{r['time_wall_s']} / {r['time_sim_s']}", "final dist to goal (m)": r.get("distance_to_goal_gt_m"),
                  "contact hits": r.get("contact_sensor_hits")} for r in runs]
        st.markdown("**Every run**")
        st.dataframe(pd.DataFrame(rows_), width="stretch", hide_index=True)
        pl = groups["planted"]
        if pl and not any(r["collision"] for r in pl) and all(verdict(r) == "FAIL" for r in pl):
            st.warning("The planted configuration FAILED the mission but did NOT collide. With the costmap obstacle/voxel layers disabled and max speed raised to 0.9 m/s the robot "
                       "could no longer plan around the box, but Nav2's collision monitor (a separate safety layer that reads /scan directly) stopped it 0.12 m short of the box "
                       "(hundreds of 'approach ... away from collision' events in out/launch_planted_*.log) and the run timed out. The collision monitor is the only thing between this change and a crash.")
        elif pl and any(r["collision"] for r in pl):
            st.error("The planted configuration collided with the box.")
        pc = ROOT / "results" / "day2_stageA" / "positive_control.txt"
        if pc.exists():
            with st.expander("Instrument check (positive control)"):
                st.code(pc.read_text(), language="text")
        shots = sorted(p for p in OUT.glob("*.png") if p.name.startswith(("gazebo_", "shot_")))
        if shots:
            for sp in shots:
                st.image(str(sp), caption=sp.name)
        else:
            st.caption("No Gazebo screenshots: the runs are headless. `GUI=true scripts/mission_test.py ...` opens the Gazebo window through WSLg for a demo video.")
