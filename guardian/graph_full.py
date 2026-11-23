#!/usr/bin/env python3
"""Standalone full-screen dependency graph -> out/graph_full.html (also copied to dashboard/static/).

Precomputed layout (no live physics): hierarchical left-to-right by dependency depth from the TurtleBot3
workspace packages. Self-contained: vis-network is inlined from guardian/vendor, so it works offline.
Default view = ROS + workspace + planted packages; a toggle adds apt + pip nodes.
"""
import collections, json, os, re, shutil, subprocess
from pathlib import Path
import networkx as nx

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "out"
TARGET = Path(os.environ.get("TARGET_DIR", ROOT / "target"))
RUNTIME_TAGS = {"depend", "exec_depend", "run_depend", "build_export_depend"}


def load(name, default):
    p = OUT / name
    return json.loads(p.read_text()) if p.exists() else default


def layout(ids, depth, edges, chunk, ygap, subgap, colgap):
    """Column = dependency depth; barycentre ordering inside a column; long columns wrap into sub-columns."""
    cols = collections.defaultdict(list)
    for n in sorted(ids):
        cols[depth[n]].append(n)
    keys = sorted(cols)
    preds, succs = collections.defaultdict(list), collections.defaultdict(list)
    for s, t in edges:
        if s in ids and t in ids:
            succs[s].append(t)
            preds[t].append(s)
    rank = {}
    for k in keys:
        for i, n in enumerate(sorted(cols[k], key=lambda n: (n.split(":")[0], n))):
            rank[n] = i / max(len(cols[k]), 1)
    for sweep in range(4):
        order = keys if sweep % 2 == 0 else keys[::-1]
        for k in order:
            nb = preds if sweep % 2 == 0 else succs
            cols[k].sort(key=lambda n: (sum(rank[x] for x in nb[n]) / len(nb[n]) if nb[n] else rank[n], n))
            for i, n in enumerate(cols[k]):
                rank[n] = i / max(len(cols[k]), 1)
    pos, x0 = {}, 0.0
    for k in keys:
        members = cols[k]
        nsub = (len(members) + chunk - 1) // chunk
        rows = min(len(members), chunk)
        for i, n in enumerate(members):
            c, r = divmod(i, chunk)
            pos[n] = [round(x0 + c * subgap, 1), round((r - rows / 2) * ygap + (c % 2) * ygap / 2, 1)]
        x0 += nsub * subgap + colgap
    return pos


def main():
    G = nx.node_link_graph(load("graph.json", {}), edges="edges")
    comps = {c["id"]: c for c in load("components.json", [])}
    prio = load("priority.json", {})
    amber_ros = prio.get("ros_amber", {})
    cves = load("cves.json", [])
    findings = load("findings.json", [])

    roots = [n for n, d in G.nodes(data=True) if d.get("layer") == "source" and d.get("kind") == "ros-package" and d["name"].startswith("turtlebot3")]
    # BFS parents (shortest path from TurtleBot3 packages, dependency direction)
    parent, dist, q = {}, {}, collections.deque()
    for r in roots:
        dist[r], parent[r] = 0, None
        q.append(r)
    while q:
        u = q.popleft()
        for v in G.successors(u):
            if v not in dist:
                dist[v], parent[v] = dist[u] + 1, u
                q.append(v)

    keep = {n for n, d in G.nodes(data=True) if d.get("layer") in ("ros", "apt", "pip") and d.get("kind") != "rosdep-key-unresolved"
            or (d.get("layer") == "source" and d.get("kind") == "ros-package")}
    # ---- planted packages (do not exist on main -> not in graph.json): new packages from findings
    planted = {}
    for f in findings:
        if f["type"] == "typosquat_name" and f["file"].endswith("package.xml"):
            name = f["component"]
            xml = subprocess.run(["git", "-C", str(TARGET), "show", f"planted:{f['file']}"], capture_output=True, text=True).stdout
            deps = re.findall(r"<(?:exec_|build_)?depend>\s*([^<\s]+)\s*</", xml)
            planted[name] = {"deps": deps, "finding": f}
    extra_edges, nodes_meta = [], {}
    owner_of = {f["dep_path"][1]: f["dep_path"][0] for f in findings if f["type"] == "unexpected_dependency" and f.get("dep_path")}
    name2id = {d["name"]: n for n, d in G.nodes(data=True) if d.get("layer") in ("ros", "source")}
    for name, info in planted.items():
        pid = f"planted:{name}"
        own = owner_of.get(name)
        oid = name2id.get(own) if own else None
        dist[pid] = (dist[oid] + 1) if oid in dist else 0
        parent[pid] = oid
        if oid:
            extra_edges.append((oid, pid, 1))
        for d in info["deps"]:
            if d in name2id:
                extra_edges.append((pid, name2id[d], 1))
        keep.add(pid)

    # ---- runtime blast radius = how many TurtleBot3 packages reach a node through runtime edges
    RG = nx.DiGraph()
    RG.add_nodes_from(G.nodes)
    for u, v, e in G.edges(data=True):
        t = set(e.get("type", "").split(","))
        if t & {"sbom-depends", "packaged-as"} or t & RUNTIME_TAGS:
            RG.add_edge(u, v)
    rset = set(roots)
    blast = {n: len(nx.ancestors(RG, n) & rset) for n in keep if n in RG}
    for name in planted:
        pid = f"planted:{name}"
        oid = name2id.get(owner_of.get(name))
        blast[pid] = len((nx.ancestors(RG, oid) | {oid}) & rset) if oid else 0

    # ---- reachable CVEs per apt/pip package (launched binaries link it)
    reach_cve = collections.defaultdict(list)
    for c in cves:
        if c.get("runtime") and c.get("reachable"):
            reach_cve[c["package"]].append(c["id"])

    maxd = max([v for n, v in dist.items() if n in keep] + [0])
    depth = {n: dist.get(n, maxd + 1) for n in keep}
    edges = [(u, v, 0) for u, v, e in G.edges(data=True) if u in keep and v in keep and e.get("type") != "contains"] + extra_edges
    small = {n for n in keep if n.startswith(("ros:", "planted:"))}
    pos_small = layout(small, depth, [(a, b) for a, b, _ in edges], chunk=45, ygap=38, subgap=210, colgap=330)
    pos_full = layout(keep, depth, [(a, b) for a, b, _ in edges], chunk=80, ygap=24, subgap=190, colgap=330)

    nodes = []
    for n in sorted(keep):
        if n.startswith("planted:"):
            name = n.split(":", 1)[1]
            f = planted[name]["finding"]
            nd = {"id": n, "label": name, "layer": "planted", "version": "(planted, branch planted)", "depth": depth[n], "blast": blast.get(n, 0),
                  "cve": 0, "amber": False, "libs": [], "rel": "planted"}
        else:
            d = G.nodes[n]
            c = comps.get(n, {})
            name = d["name"]
            layer = d["layer"]
            if layer == "ros" or layer == "source":
                libs = amber_ros.get(name, {})
                amber, cvec = bool(libs), sum(v["cves"] for v in libs.values())
                liblist = [f"{k} ({v['cves']} CVEs, worst {v['worst']}) via {v['binary']}" for k, v in libs.items()]
            else:
                ids = sorted(set(reach_cve.get(name, [])))
                amber, cvec = bool(ids), c.get("cve_count", 0)
                liblist = [f"{len(ids)} reachable CVEs: " + ", ".join(ids[:6]) + (" …" if len(ids) > 6 else "")] if ids else []
            nd = {"id": n, "label": name, "layer": "source" if (d.get("layer") == "source") else layer, "version": d.get("version", ""),
                  "depth": depth[n], "blast": blast.get(n, 0), "cve": cvec, "amber": amber, "libs": liblist, "rel": c.get("relation", "")}
        nd["parent"] = parent.get(n)
        nd["find"] = [f"{f['id']} {f['type']} ({f['risk']}) {f['file']}:{f['line']}" for f in findings
                      if f["component"] == nd["label"] and (nd["layer"] in ("planted", "ros", "source") or f["layer"] == nd["layer"])]
        if n in pos_small:
            nd["ps"] = pos_small[n]
        nd["pf"] = pos_full[n]
        nodes.append(nd)
    data = {"nodes": nodes, "edges": [[a, b, p] for a, b, p in edges],
            "counts": {"small": len(small), "full": len(keep)}, "roots": len(roots)}
    payload = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    lib = (ROOT / "guardian" / "vendor" / "vis-network.min.js").read_text()
    html = HTML.replace("/*VIS_JS*/", lib.replace("</script", "<\\/script")).replace("__DATA__", payload)
    (OUT / "graph_full.html").write_text(html)
    static = ROOT / "dashboard" / "static"
    static.mkdir(exist_ok=True)
    shutil.copy(OUT / "graph_full.html", static / "graph_full.html")
    print(f"graph_full.html: {len(small)} nodes default / {len(keep)} with apt+pip, {len(edges)} edges, {len(html) // 1024} KB, {len(planted)} planted, "
          f"{sum(n['amber'] for n in nodes)} amber")


HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Supply Chain Guardian - dependency graph</title>
<style>
html,body{margin:0;height:100%;background:#0e1117;color:#e6e6e6;font:14px/1.4 system-ui,sans-serif;overflow:hidden}
#net{position:absolute;inset:0}
.box{position:absolute;background:rgba(22,27,34,.94);border:1px solid #30363d;border-radius:8px;padding:10px 12px;z-index:5}
#top{top:10px;left:10px;display:flex;gap:12px;align-items:center;flex-wrap:wrap;max-width:calc(100% - 420px)}
#top input[type=text]{background:#0d1117;color:#e6e6e6;border:1px solid #444c56;border-radius:6px;padding:6px 8px;width:230px}
#top button{background:#238636;color:#fff;border:0;border-radius:6px;padding:6px 10px;cursor:pointer}
#legend{bottom:10px;left:10px;font-size:13px}
#legend div{display:flex;align-items:center;gap:8px;margin:3px 0}
.dot{width:14px;height:14px;border-radius:50%;display:inline-block;box-sizing:border-box}
#panel{top:10px;right:10px;width:380px;max-height:calc(100% - 20px);overflow:auto;display:none}
#panel h3{margin:0 0 6px;font-size:16px;word-break:break-all}
#panel table{border-collapse:collapse;width:100%}#panel td{padding:2px 4px;vertical-align:top}#panel td:first-child{color:#8b949e;white-space:nowrap}
#panel .x{position:absolute;top:6px;right:10px;cursor:pointer;color:#8b949e}
.risk{color:#ff7b72}.small{font-size:12px;color:#8b949e}
</style></head><body>
<div id="net"></div>
<div id="top" class="box">
  <b>Dependency graph</b>
  <input id="q" type="text" list="names" placeholder="Search package (Enter to zoom)"><datalist id="names"></datalist>
  <label><input id="tog" type="checkbox"> show apt &amp; pip (<span id="cfull"></span> nodes)</label>
  <button id="fit">Fit</button><span class="small" id="stat"></span>
</div>
<div id="legend" class="box">
  <b>Legend</b>
  <div><span class="dot" style="background:#ff7f0e"></span>TurtleBot3 workspace</div>
  <div><span class="dot" style="background:#1f77b4"></span>ROS package (image)</div>
  <div><span class="dot" style="background:#8a8f98"></span>apt package</div>
  <div><span class="dot" style="background:#2ca02c"></span>pip package</div>
  <div><span class="dot" style="background:#e53935"></span>suspicious / planted</div>
  <div><span class="dot" style="background:#1f77b4;border:4px solid #ffc107"></span>amber border = reachable CVEs via a direct link</div>
  <div class="small">size = runtime blast radius (TurtleBot3 packages that depend on it)<br>columns = dependency depth from TurtleBot3 (left &rarr; right); arrows point to the dependency<br>last column = in the image but not used by TurtleBot3<br>click a node: highlight its path from TurtleBot3</div>
</div>
<div id="panel" class="box"><span class="x" onclick="clearSel()">&#10005;</span><div id="pc"></div></div>
<script>/*VIS_JS*/</script>
<script>
const D = __DATA__;
const COL = {source:"#ff7f0e", ros:"#1f77b4", apt:"#8a8f98", pip:"#2ca02c", planted:"#e53935"};
const AMBER = "#ffc107", EDGE = "rgba(150,160,175,0.28)";
const byId = {}; D.nodes.forEach(n => byId[n.id] = n);
const isBig = n => n.layer === "apt" || n.layer === "pip";
let full = false;
function sz(n){ if (n.layer==="planted") return 22; if (n.layer==="source" && n.depth===0) return 20; return 6 + 3.2*n.blast; }
function vnode(n){
  const big = (n.layer==="planted") || (n.layer==="source" && n.depth===0);
  const p = full ? n.pf : (n.ps || n.pf);
  return {id:n.id, label:n.label, x:p[0], y:p[1], shape:"dot", size:sz(n), hidden: !full && isBig(n),
    color:{background:COL[n.layer]||"#888", border:n.amber?AMBER:(n.layer==="planted"?"#fff":(COL[n.layer]||"#888")),
           highlight:{background:COL[n.layer]||"#888", border:"#fff"}, hover:{background:COL[n.layer]||"#888", border:"#fff"}},
    borderWidth:n.amber?4:(n.layer==="planted"?3:1), font:{size:big?24:14, color:"#e6e6e6", strokeWidth:3, strokeColor:"#0e1117"}, opacity:1};
}
const nodes = new vis.DataSet(D.nodes.map(vnode));
const edges = new vis.DataSet(D.edges.map(e => ({id:e[0]+">"+e[1], from:e[0], to:e[1],
  color:{color:e[2]?"#e53935":EDGE, opacity:e[2]?1:1}, width:e[2]?2.5:1, arrows:{to:{enabled:true, scaleFactor:0.4}}, smooth:false})));
const PE = new Set(D.edges.filter(e => e[2]).map(e => e[0]+">"+e[1]));
const net = new vis.Network(document.getElementById("net"), {nodes, edges}, {
  physics:false, layout:{improvedLayout:false},
  interaction:{hover:true, hideEdgesOnDrag:true, hideEdgesOnZoom:true, tooltipDelay:150, dragNodes:true},
  nodes:{scaling:{label:{enabled:false, drawThreshold:9, maxVisible:30}}}, edges:{selectionWidth:2}
});
document.getElementById("cfull").textContent = D.counts.full.toLocaleString();
const dl = document.getElementById("names");
D.nodes.forEach(n => { const o=document.createElement("option"); o.value=n.label; dl.appendChild(o); });
function stat(){ document.getElementById("stat").textContent = (full?D.counts.full:D.counts.small).toLocaleString()+" nodes shown"; }
function setFull(v){
  full = v; document.getElementById("tog").checked = v;
  nodes.update(D.nodes.map(n => { const p = full ? n.pf : (n.ps || n.pf); return {id:n.id, x:p[0], y:p[1], hidden: !full && isBig(n)}; }));
  clearSel(); stat(); setTimeout(() => net.fit({animation:false}), 50);
}
document.getElementById("tog").onchange = e => setFull(e.target.checked);
document.getElementById("fit").onclick = () => net.fit({animation:{duration:300}});
let hl = {nodes:[], edges:[]};
function clearSel(){
  document.getElementById("panel").style.display = "none";
  if (hl.nodes.length) {
    nodes.update(D.nodes.map(n => ({id:n.id, opacity:1})));
    edges.update(hl.edges.map(id => ({id, color:{color:PE.has(id)?"#e53935":EDGE}, width:PE.has(id)?2.5:1})));
  }
  hl = {nodes:[], edges:[]}; net.unselectAll();
}
function pathTo(id){ const p=[]; let c=id; while(c){ p.push(c); c=byId[c].parent; } return p.reverse(); }
function esc(s){ return String(s).replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c])); }
function showNode(id){
  const n = byId[id]; if (!n) return;
  clearSel();
  const path = pathTo(id), set = new Set(path);
  nodes.update(D.nodes.map(m => ({id:m.id, opacity:set.has(m.id)?1:0.12})));
  const eids = []; for (let i=0;i<path.length-1;i++) eids.push(path[i]+">"+path[i+1]);
  const upd = eids.filter(i => edges.get(i)).map(i => ({id:i, color:{color:AMBER}, width:4}));
  edges.update(upd); hl = {nodes:path, edges:upd.map(u=>u.id)};
  const rows = [["Layer", n.layer], ["Version", n.version||"-"], ["Relation", n.rel||"-"], ["Depth", n.depth],
    ["Runtime blast radius", n.blast+" of "+D.roots+" TurtleBot3 packages depend on it"],
    ["CVE count", n.cve + (n.amber ? " (reachable via a direct link)" : "")]];
  let h = "<h3>"+esc(n.label)+"</h3><table>"+rows.map(r => "<tr><td>"+r[0]+"</td><td>"+esc(r[1])+"</td></tr>").join("")+"</table>";
  if (n.libs.length) h += "<p><b>Reachable CVE links</b></p><ul class='small'>"+n.libs.map(l => "<li>"+esc(l)+"</li>").join("")+"</ul>";
  h += "<p><b>Findings</b></p>" + (n.find.length ? "<ul>"+n.find.map(f => "<li class='risk'>"+esc(f)+"</li>").join("")+"</ul>" : "<span class='small'>none</span>");
  h += "<p><b>Path from TurtleBot3</b></p><div class='small'>"+(n.parent!==null||n.depth===0 ? path.map(p => esc(byId[p].label)).join(" &rarr; ") : "not used by TurtleBot3 (base image only)")+"</div>";
  document.getElementById("pc").innerHTML = h; document.getElementById("panel").style.display = "block";
}
net.on("click", p => { if (p.nodes.length) showNode(p.nodes[0]); else clearSel(); });
function find(q){
  q = q.trim().toLowerCase(); if (!q) return;
  const c = D.nodes.filter(n => n.label.toLowerCase()===q).concat(D.nodes.filter(n => n.label.toLowerCase().startsWith(q)), D.nodes.filter(n => n.label.toLowerCase().includes(q)));
  if (!c.length) { document.getElementById("stat").textContent = "no match for '"+q+"'"; return; }
  const n = c[0]; if (isBig(n) && !full) setFull(true);
  net.selectNodes([n.id]); net.focus(n.id, {scale:1.4, animation:{duration:500}}); showNode(n.id);
}
const qi = document.getElementById("q");
qi.addEventListener("keydown", e => { if (e.key==="Enter") find(qi.value); });
qi.addEventListener("change", () => find(qi.value));
stat(); net.once("afterDrawing", () => net.fit({animation:false}));
</script></body></html>
"""

if __name__ == "__main__":
    main()
