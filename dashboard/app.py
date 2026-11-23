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
def load(name, default):
    p = OUT / name
    return json.loads(p.read_text()) if p.exists() else default


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

tab_in, tab_chg, tab_risk = st.tabs(["What's inside", "What changed", "What's risky"])

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
    st.subheader("TurtleBot3 top-level packages and their direct dependencies")
    try:
        from pyvis.network import Network
        G = nx.node_link_graph(graph, edges="edges")
        roots = [n for n, d in G.nodes(data=True) if d.get("layer") == "source" and d.get("kind") == "ros-package"
                 and d["name"].startswith("turtlebot3")]
        net = Network(height="560px", width="100%", directed=True, bgcolor="#0e1117", font_color="white")
        colour = {"source": "#ff7f0e", "ros": "#1f77b4", "apt": "#2ca02c", "pip": "#9467bd"}
        AMBER, RED = "#ffc107", "#e53935"
        reach_ros = {c["ros_package"] for c in cves if c.get("reachable") and c.get("ros_package")}
        sub = set(roots)
        for r in roots:
            sub.update(s for s in G.successors(r) if G.nodes[s].get("layer") in ("source", "ros"))
        for n in sub:
            d = G.nodes[n]
            has_cve = d["name"] in reach_ros
            net.add_node(n, label=d["name"], shape="dot", size=28 if n in roots else 18,
                         color={"background": colour.get(d["layer"], "#888"), "border": AMBER if has_cve else colour.get(d["layer"], "#888"),
                                "highlight": {"background": colour.get(d["layer"], "#888"), "border": "#fff"}},
                         borderWidth=5 if has_cve else 1, font={"size": 20, "color": "#ffffff", "strokeWidth": 3, "strokeColor": "#0e1117"},
                         title=f"{d['layer']} {d.get('version', '')}" + (" - has reachable CVEs" if has_cve else ""))
        for u, w in G.edges(sub):
            if u in sub and w in sub:
                net.add_edge(u, w, color="#888888")
        # planted / suspicious packages from the findings (they do not exist on main, so not in graph.json)
        for f in findings:
            if f["type"] == "unexpected_dependency" and f.get("dep_path"):
                owner, dep = f["dep_path"]
                oid = next((n for n in sub if G.nodes[n]["name"] == owner), None)
                if oid:
                    net.add_node(f"sus:{dep}", label=dep, shape="dot", size=24, color={"background": RED, "border": "#ffffff"}, borderWidth=3,
                                 font={"size": 20, "color": "#ffffff", "strokeWidth": 3, "strokeColor": "#0e1117"},
                                 title=f"{f['risk']} - {f['type']} ({f['file']}:{f['line']})")
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
        st.caption("orange = TurtleBot3 workspace, blue = ROS packages in the image, red = suspicious/planted, amber border = has reachable CVEs "
                   "(layout is frozen after stabilisation; drag nodes to rearrange)")
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
        st.subheader("Top 10 CVEs that matter")
        st.markdown(f"**{fn['total']:,} CVEs → {fn['in_robot_tree']:,} in the robot's tree → {fn['runtime']:,} runtime → "
                    f"{fn['reachable']:,} reachable → top 10**")
        fc = st.columns(5)
        for col, (lab, k) in zip(fc, [("All CVEs", "total"), ("In robot's tree", "in_robot_tree"), ("Runtime", "runtime"), ("Reachable", "reachable"), ("Shown", "top")]):
            col.metric(lab, f"{fn[k]:,}")
        st.caption("In tree = a TurtleBot3 dependency path reaches the package · runtime = not build/dev-only · reachable = linked (ldd) by "
                   f"binaries of the {len(fn['launched_packages'])} packages started by the TurtleBot3 launch files ({fn['binaries_scanned']} binaries scanned) or imported by Python nodes. "
                   "Max 3 CVEs per package.")
        for i, t in enumerate(prio["top10"], 1):
            with st.expander(f"{i}. {t['id']} · {t['severity']} · {t['package']} {t['installed']} · priority {t['score']}"):
                st.markdown("**Why it ranks here:** " + " · ".join(t["priority_reasons"]))
                st.markdown(f"Exposure: **{t['exposure']}** · Reachability: {t['reachability']} · Provenance: {t['provenance']}")
                if t["path"]:
                    st.markdown("Path: " + " → ".join(f"`{p}`" for p in t["path"]))
        st.divider()
        st.subheader("All risks")
    rows = []
    for f in findings:
        rows.append({"kind": "suspicious", "id": f["id"], "risk": f["risk"], "layer": f["layer"],
                     "component": f["component"], "summary": f"{f['type']}: {f['reason']}", "priority": 100.0 - RISK_RANK[f["risk"]], "ref": ("f", f["id"])})
    for i, c in enumerate(cves):
        rows.append({"kind": "CVE", "id": c["id"], "risk": c["severity"].lower(), "layer": c["layer"],
                     "component": f"{c['package']} {c['installed']}",
                     "summary": f"{c.get('exposure', '?')} · fixed in {c['fixed']}" if c["fixed"] else f"{c.get('exposure', '?')} · no fix available",
                     "priority": c.get("score", 0.0), "ref": ("c", i)})
    rk = pd.DataFrame(rows)
    rk["rank"] = rk["risk"].map(lambda r: RISK_RANK.get(r, 9))
    rk["_k"] = (rk["kind"] != "suspicious").astype(int)
    sort_by = st.radio("Sort by", ["Priority score (findings first, then CVEs by score)", "Severity"], horizontal=True)
    rk = (rk.sort_values(["priority", "rank"], ascending=[False, True]) if sort_by.startswith("Priority")
          else rk.sort_values(["rank", "_k", "priority"], ascending=[True, True, False])).reset_index(drop=True)
    f1, f2, f3 = st.columns([2, 2, 3])
    lay = f1.multiselect("Layer", sorted(rk["layer"].unique()))
    rsk = f2.multiselect("Risk", ["critical", "high", "medium", "low"], default=["critical", "high"])
    srch = f3.text_input("Search id / component / summary", "")
    v = rk
    if lay:
        v = v[v["layer"].isin(lay)]
    if rsk:
        v = v[v["risk"].isin(rsk)]
    if srch:
        m = v[["id", "component", "summary"]].astype(str).apply(lambda c: c.str.contains(srch, case=False)).any(axis=1)
        v = v[m]
    v = v.reset_index(drop=True)
    st.caption(f"{len(v)} rows ({(v['kind']=='suspicious').sum()} suspicious findings, {(v['kind']=='CVE').sum()} CVEs) — click a row for evidence")
    show = v.assign(risk=v["risk"].map(lambda r: f"{ICON.get(r, '')} {r}"))[["risk", "priority", "kind", "id", "layer", "component", "summary"]]
    st.caption("CVEs from Trivy and suspicious changes from the diff in one list; priority = severity × exposure × reachability × provenance × fix (findings are always above CVEs). Click a row for its evidence.")
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
                if c.get("ros_package"):
                    st.write(f"Nearest ROS package on path: `{c['ros_package']}`")
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
