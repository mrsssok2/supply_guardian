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
    df["path"] = df["path"].apply(lambda p: " → ".join(p) if p else "(not reachable from turtlebot3)")
    left, right = st.columns([1, 1])
    with left:
        st.subheader("Components per layer")
        st.bar_chart(df["layer"].value_counts())
    with right:
        st.subheader("Direct vs transitive")
        rel = pd.crosstab(df["layer"], df["relation"])
        st.dataframe(rel, width='stretch')
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

    st.subheader("TurtleBot3 top-level packages and their direct dependencies")
    try:
        from pyvis.network import Network
        G = nx.node_link_graph(graph, edges="edges")
        roots = [n for n, d in G.nodes(data=True) if d.get("layer") == "source" and d.get("kind") == "ros-package"
                 and d["name"].startswith("turtlebot3")]
        net = Network(height="480px", width="100%", directed=True, bgcolor="#0e1117", font_color="white")
        colour = {"source": "#ff7f0e", "ros": "#1f77b4", "apt": "#2ca02c", "pip": "#9467bd"}
        sub = set(roots)
        for r in roots:
            sub.update(s for s in G.successors(r) if G.nodes[s].get("layer") in ("source", "ros"))
        for n in sub:
            d = G.nodes[n]
            net.add_node(n, label=d["name"], color=colour.get(d["layer"], "#888"),
                         size=22 if n in roots else 12, title=f"{d['layer']} {d.get('version', '')}")
        for u, w in G.edges(sub):
            if u in sub and w in sub:
                net.add_edge(u, w)
        net.toggle_physics(True)
        components.html(net.generate_html(notebook=False), height=500)
        st.caption("orange = workspace (source) packages, blue = ROS packages in the image")
    except Exception as e:  # graph is a nicety, never block the demo
        st.info(f"Graph unavailable: {e}")

# ------------------------------------------------------------------ changed
with tab_chg:
    st.subheader("main → planted")
    if not changes:
        st.info("No changes.json - run guardian/suspicious.py")
    else:
        flagged = {(f["file"], f["line"]): f for f in findings}
        cd = pd.DataFrame(changes)
        cd["flagged"] = cd.apply(lambda r: flagged[(r["file"], r["line"])]["type"] if (r["file"], r["line"]) in flagged else "", axis=1)
        fmt = lambda x: x.strip() if isinstance(x, str) else "∅"
        cd["old → new"] = cd.apply(lambda r: f"{fmt(r['old'])}  →  {fmt(r['new'])}", axis=1)
        files = sorted(cd["file"].unique())
        sel = st.multiselect("File", files)
        only = st.checkbox("Only flagged lines", False)
        v = cd[cd["file"].isin(sel)] if sel else cd
        if only:
            v = v[v["flagged"] != ""]
        st.caption(f"{len(changes)} changed lines in {len(files)} files · {len(v)} shown")
        st.dataframe(v[["file", "line", "status", "old → new", "flagged"]], width='stretch',
                     hide_index=True, height=520)

# ------------------------------------------------------------------ risky
with tab_risk:
    rows = []
    for f in findings:
        rows.append({"kind": "suspicious", "id": f["id"], "risk": f["risk"], "layer": f["layer"],
                     "component": f["component"], "summary": f"{f['type']}: {f['reason']}", "ref": ("f", f["id"])})
    for i, c in enumerate(cves):
        rows.append({"kind": "CVE", "id": c["id"], "risk": c["severity"].lower(), "layer": c["layer"],
                     "component": f"{c['package']} {c['installed']}",
                     "summary": f"fixed in {c['fixed']}" if c["fixed"] else "no fix available" ,
                     "ref": ("c", i)})
    rk = pd.DataFrame(rows)
    rk["rank"] = rk["risk"].map(lambda r: RISK_RANK.get(r, 9))
    rk["_k"] = (rk["kind"] != "suspicious").astype(int)
    rk = rk.sort_values(["rank", "_k"]).reset_index(drop=True)
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
    show = v.assign(risk=v["risk"].map(lambda r: f"{ICON.get(r, '')} {r}"))[["risk", "kind", "id", "layer", "component", "summary"]]
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
                st.caption(f"source: {a['source']} · verdict: {a['verdict']}")
            elif kind == "f":
                st.warning("No AI verdict for this finding (only critical/high are analysed; run guardian/agent.py).")
            else:
                st.write("AI analysis covers suspicious findings only, not CVE rows.")
