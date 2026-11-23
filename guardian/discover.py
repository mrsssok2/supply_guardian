#!/usr/bin/env python3
"""STEP 2 - discover: what is inside the robot software.

Runs Trivy on the robot image (SBOM + vulns), parses every package.xml (workspace + the
image's /opt/ros/jazzy/share), builds a networkx dependency graph and writes
out/components.json, out/graph.json, out/cves.json.  Detection only; everything local.
"""
import io, json, os, re, shutil, subprocess, sys, tarfile, collections
import xml.etree.ElementTree as ET
from pathlib import Path
import networkx as nx

ROOT = Path(__file__).resolve().parent.parent
TARGET = Path(os.environ.get("TARGET_DIR", ROOT / "target"))
OUT = ROOT / "out"
IMAGE = os.environ.get("ROBOT_IMAGE", "gurdy2/ros:jazzy")
TRIVY = shutil.which("trivy") or str(Path.home() / ".local/bin/trivy")
DEP_TAGS = ("depend", "build_depend", "test_depend", "exec_depend", "build_export_depend",
            "buildtool_depend", "buildtool_export_depend", "run_depend")
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


# ---------------------------------------------------------------- trivy
def run_trivy(force=False):
    OUT.mkdir(exist_ok=True)
    sbom, vulns = OUT / "sbom.cdx.json", OUT / "vulns.json"
    if force or not sbom.exists():
        sh([TRIVY, "image", "--scanners", "vuln", "--format", "cyclonedx", "--output", str(sbom), IMAGE])
    if force or not vulns.exists():
        sh([TRIVY, "image", "--scanners", "vuln", "--format", "json", "--output", str(vulns), IMAGE])
    return json.loads(sbom.read_text()), json.loads(vulns.read_text())


# ---------------------------------------------------------------- package.xml
def parse_package_xml(text):
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    name = (root.findtext("name") or "").strip()
    if not name:
        return None
    deps = collections.OrderedDict()
    for tag in DEP_TAGS:
        for el in root.findall(tag):
            if el.text and el.text.strip():
                deps.setdefault(el.text.strip(), set()).add(tag)
    return {"name": name, "version": (root.findtext("version") or "").strip(),
            "deps": {k: sorted(v) for k, v in deps.items()}}


def workspace_packages():
    pk = {}
    src = TARGET / "robot_ws" / "src"
    for f in sorted(src.rglob("package.xml")):
        p = parse_package_xml(f.read_text(errors="replace"))
        if p:
            p["file"] = str(f.relative_to(TARGET))
            p["repo"] = f.relative_to(src).parts[0]
            pk[p["name"]] = p
    return pk


def image_ros_packages():
    """Stream every /opt/ros/jazzy/share/*/package.xml out of the image (docker run --rm)."""
    cmd = ["docker", "run", "--rm", IMAGE, "bash", "-c",
           "cd /opt/ros/jazzy/share && find . -maxdepth 2 -name package.xml -print0 | tar --null -T - -cf -"]
    data = sh(cmd, stdout=subprocess.PIPE).stdout
    pk = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for m in tf.getmembers():
            if m.isfile():
                p = parse_package_xml(tf.extractfile(m).read().decode(errors="replace"))
                if p:
                    p["file"] = "/opt/ros/jazzy/share/" + m.name.lstrip("./")
                    pk[p["name"]] = p
    return pk


# ---------------------------------------------------------------- other inputs
def parse_repos():
    import yaml
    f = TARGET / "robot.repos"
    if not f.exists():
        return {}
    return (yaml.safe_load(f.read_text()) or {}).get("repositories", {})


def parse_dockerfile():
    f = TARGET / "Dockerfile"
    froms = []
    if f.exists():
        for i, line in enumerate(f.read_text().splitlines(), 1):
            m = re.match(r"\s*FROM\s+(\S+)", line, re.I)
            if m:
                froms.append((m.group(1), i))
    return froms


def parse_workflows():
    import yaml
    acts = []
    for f in sorted((TARGET / ".github" / "workflows").glob("*.y*ml")) if (TARGET / ".github/workflows").exists() else []:
        for i, line in enumerate(f.read_text().splitlines(), 1):
            m = re.search(r"uses:\s*([^\s#]+)", line)
            if m:
                acts.append((m.group(1), str(f.relative_to(TARGET)), i))
    return acts


# ---------------------------------------------------------------- build graph
def build():
    sbom, vulns = run_trivy()
    ws = workspace_packages()
    img = image_ros_packages()
    G = nx.DiGraph()

    def add(nid, **a):
        if nid not in G:
            G.add_node(nid, **a)
        else:
            G.nodes[nid].update({k: v for k, v in a.items() if v is not None})

    # image + base layer
    image_id = f"image:{IMAGE}"
    add(image_id, name=IMAGE, version="", layer="image", kind="image")
    for ref, line in parse_dockerfile():
        add(f"image:{ref}", name=ref, version="", layer="image", kind="base-image", file="Dockerfile", line=line)

    # apt + pip from SBOM
    purl2id, apt_names = {}, {}
    for c in sbom.get("components", []):
        purl = c.get("purl", "")
        if purl.startswith("pkg:deb"):
            nid, layer = f"apt:{c['name']}", "apt"
            apt_names[c["name"]] = nid
        elif purl.startswith("pkg:pypi"):
            nid, layer = f"pip:{c['name']}", "pip"
        else:
            continue
        add(nid, name=c["name"], version=c.get("version", ""), layer=layer, kind="package", purl=purl)
        purl2id[c.get("bom-ref", purl)] = nid
    for d in sbom.get("dependencies", []):
        a = purl2id.get(d["ref"])
        for r in d.get("dependsOn", []):
            b = purl2id.get(r)
            if a and b and a != b:
                G.add_edge(a, b, type="sbom-depends")

    # ROS packages (image first, workspace overrides -> layer 'source')
    for name, p in img.items():
        add(f"ros:{name}", name=name, version=p["version"], layer="ros", kind="ros-package", file=p["file"])
    for name, p in ws.items():
        add(f"ros:{name}", name=name, version=p["version"], layer="source", kind="ros-package",
            file=p["file"], repo=p["repo"])
    allros = {**img, **ws}
    for name, p in allros.items():
        nid = f"ros:{name}"
        apt = apt_names.get("ros-jazzy-" + name.replace("_", "-"))
        if apt:
            G.add_edge(nid, apt, type="packaged-as")
        for dep, tags in p["deps"].items():
            if dep in allros:
                G.add_edge(nid, f"ros:{dep}", type=",".join(tags))
            elif dep in apt_names:
                G.add_edge(nid, apt_names[dep], type=",".join(tags))
            elif f"python3-{dep.replace('python3-','')}" in apt_names:
                G.add_edge(nid, apt_names[f"python3-{dep.replace('python3-','')}"], type=",".join(tags))
            else:  # rosdep key we cannot resolve to an installed apt package
                add(f"rosdep:{dep}", name=dep, version="", layer="apt", kind="rosdep-key-unresolved")
                G.add_edge(nid, f"rosdep:{dep}", type=",".join(tags))

    # source repos (robot.repos) -> packages
    for rname, r in parse_repos().items():
        rid = f"repo:{rname}"
        add(rid, name=rname, version=str(r.get("version", "")), layer="source", kind="repo",
            file="robot.repos", url=r.get("url"))
        for pn, p in ws.items():
            if p["repo"] == rname:
                G.add_edge(rid, f"ros:{pn}", type="contains")
    # CI
    for act, f, line in parse_workflows():
        add(f"ci:{act}", name=act, version=act.split("@")[-1] if "@" in act else "", layer="ci",
            kind="github-action", file=f, line=line)

    return G, sbom, vulns, ws


def analyse(G, vulns, ws):
    # shortest path (dependency direction) from turtlebot3 packages
    seeds = [f"ros:{n}" for n, p in ws.items() if n.startswith("turtlebot3")]
    dist, parent = {}, {}
    q = collections.deque()
    for s in seeds:
        dist[s] = 0
        parent[s] = None
        q.append(s)
    while q:
        u = q.popleft()
        for v in G.successors(u):
            if v not in dist:
                dist[v], parent[v] = dist[u] + 1, u
                q.append(v)

    def path_to(n):
        out = []
        while n is not None:
            out.append(n)
            n = parent[n]
        return out[::-1]

    cves = collections.defaultdict(list)
    comps = []
    for r in vulns.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            nid = f"apt:{v['PkgName']}" if r["Class"] == "os-pkgs" else f"pip:{v['PkgName']}"
            cves[nid].append(v)
    cve_list = []
    for nid, d in G.nodes(data=True):
        rel = "workspace root" if dist.get(nid) == 0 else "direct" if dist.get(nid) == 1 else \
              "transitive" if nid in dist else "base image only"
        path = [G.nodes[x]["name"] for x in path_to(nid)] if nid in dist else []
        comps.append({"id": nid, "name": d["name"], "version": d.get("version", ""), "layer": d["layer"],
                      "kind": d.get("kind"), "relation": rel, "distance": dist.get(nid),
                      "path": path, "file": d.get("file"), "cve_count": len(cves.get(nid, []))})
    for nid, vs in cves.items():
        if nid not in G:
            continue
        p = path_to(nid) if nid in dist else []
        ros_on_path = [x for x in p if x.startswith("ros:")]
        for v in vs:
            cve_list.append({
                "id": v["VulnerabilityID"], "severity": v.get("Severity", "UNKNOWN"),
                "package": v["PkgName"], "installed": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion") or "", "layer": G.nodes[nid]["layer"],
                "title": v.get("Title", ""), "status": v.get("Status", ""),
                "path": [G.nodes[x]["name"] for x in p],
                "ros_package": G.nodes[ros_on_path[-1]]["name"] if ros_on_path else None,
                "url": v.get("PrimaryURL", "")})
    cve_list.sort(key=lambda c: -SEV_ORDER.get(c["severity"], 0))
    return comps, cve_list


def main():
    G, sbom, vulns, ws = build()
    comps, cve_list = analyse(G, vulns, ws)
    (OUT / "components.json").write_text(json.dumps(comps, indent=1))
    (OUT / "cves.json").write_text(json.dumps(cve_list, indent=1))
    (OUT / "graph.json").write_text(json.dumps(nx.node_link_data(G, edges="edges"), indent=1))
    layers = collections.Counter(c["layer"] for c in comps if c["kind"] != "rosdep-key-unresolved")
    print("components per layer:", dict(layers))
    print("relation:", dict(collections.Counter(c["relation"] for c in comps)))
    print("unresolved rosdep keys:", sum(c["kind"] == "rosdep-key-unresolved" for c in comps))
    print("graph:", G.number_of_nodes(), "nodes,", G.number_of_edges(), "edges")
    sev = collections.Counter(c["severity"] for c in cve_list)
    print("CVEs:", len(cve_list), dict(sev), "| with ROS-package path:", sum(bool(c["ros_package"]) for c in cve_list))


if __name__ == "__main__":
    main()
