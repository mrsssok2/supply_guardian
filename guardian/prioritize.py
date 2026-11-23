#!/usr/bin/env python3
"""CVE prioritisation: which of the Trivy CVEs actually matter for the robot?

Signals (all from tools/files, nothing guessed):
  exposure     runtime (reachable from TurtleBot3 through exec/depend/export/apt-Depends edges)
               | build/dev-only (-dev, headers, compilers, build_depend/test_depend-only paths)
               | base image only (no TurtleBot3 dependency path)
  reachability C/C++: library is in the ldd closure of executables/libs of the ROS packages that the TurtleBot3
               launch files start (resolved with dpkg -S inside the image); Python: imported by those nodes.
  provenance   Ubuntu archive | ROS apt repo | PyPI | unknown (from the SBOM purl/supplier)
  severity, fix available
Writes the fields into out/cves.json and out/priority.json (funnel + top 10).
"""
import collections, json, os, re, subprocess, sys, ast
from pathlib import Path
import networkx as nx

ROOT = Path(__file__).resolve().parent.parent
TARGET = Path(os.environ.get("TARGET_DIR", ROOT / "target"))
OUT = ROOT / "out"
IMAGE = os.environ.get("ROBOT_IMAGE", "gurdy2/ros:jazzy")
RUNTIME_TAGS = {"depend", "exec_depend", "run_depend", "build_export_depend"}
BUILD_ONLY = re.compile(
    r"(-dev$|^linux-libc-dev|^libc6-dev|^(gcc|g\+\+|cpp|clang|llvm|make|cmake|binutils|build-essential|dpkg-dev|pkg-config|pkgconf|"
    r"autoconf|automake|libtool|m4|patch|flex|bison|cython3?|python3-dev|python3-pytest|python3-setuptools-scm)(-\d+)?(-|$)|-doc$|"
    r"^ament-(lint|cppcheck|flake8|pep257|copyright|xmllint|uncrustify|cpplint|mypy)|^ros-jazzy-ament-(lint|cppcheck|flake8|pep257|copyright|xmllint|uncrustify|cpplint|mypy)|"
    r"^ros-jazzy-.*-(dev|dbgsym)$|^ros-jazzy-gtest|^googletest|^libgtest)")
BASE_LIBS = re.compile(r"^(libc6|libstdc\+\+6|libgcc-s1|libpython3\.12.*)$")  # ubiquitous: do not make a ROS package "amber" on their own
BASE = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "UNKNOWN": 2}
EXPO_MULT = {"runtime": 1.0, "build/dev-only": 0.2, "base image only": 0.4}
PROV_MULT = {"Ubuntu archive": 1.0, "ROS apt repo": 1.0, "PyPI": 1.15, "unknown": 1.3}

INSIDE = r'''
import os, re, sys, json, glob, subprocess, ast, importlib.util
seeds = json.load(sys.stdin)
SHARE, LIB = "/opt/ros/jazzy/share", "/opt/ros/jazzy/lib"
pat = re.compile(r"package\s*=\s*['\"](\w+)['\"]|get_package_share_directory\(\s*['\"](\w+)['\"]|FindPackageShare\(\s*['\"](\w+)['\"]")
seen, queue = set(), [(p, 0) for p in seeds]
while queue:
    p, d = queue.pop()
    if p in seen: continue
    seen.add(p)
    if d >= 4: continue
    for f in glob.glob(f"{SHARE}/{p}/launch/**/*.py", recursive=True):
        for m in pat.finditer(open(f, errors="replace").read()):
            queue.append((next(g for g in m.groups() if g), d + 1))
targets = []
for p in seen:
    targets += [x for x in glob.glob(f"{LIB}/{p}/*") if os.path.isfile(x)]
    targets += glob.glob(f"{LIB}/lib{p}*.so*")
libs, pyimports, nexe = {}, {}, 0
for t in sorted(set(targets)):
    try: head = open(t, "rb").read(4)
    except Exception: continue
    if head == b"\x7fELF":
        nexe += 1
        out = subprocess.run(["ldd", t], capture_output=True, text=True).stdout
        for m in re.finditer(r"=>\s*(/\S+)", out):
            libs.setdefault(os.path.realpath(m.group(1)), os.path.basename(t))
    elif head[:2] == b"#!":
        try: tree = ast.parse(open(t, errors="replace").read())
        except Exception: continue
        for n in ast.walk(tree):
            mods = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module] if isinstance(n, ast.ImportFrom) and n.module and n.level == 0 else []
            for mod in mods:
                top = mod.split(".")[0]
                try: spec = importlib.util.find_spec(top)
                except Exception: spec = None
                path = None
                if spec:
                    if spec.origin not in (None, "frozen", "built-in"): path = spec.origin
                    elif spec.submodule_search_locations: path = list(spec.submodule_search_locations)[0]
                if path and path.startswith(("/usr", "/opt")): pyimports.setdefault(os.path.realpath(path), os.path.basename(t))
def owners(paths):
    res = {}
    paths = list(paths)
    for i in range(0, len(paths), 150):
        chunk = paths[i:i+150]
        out = subprocess.run(["dpkg", "-S", *chunk], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if ": /" in line:
                pk, path = line.rsplit(": /", 1)
                for name in pk.split(", "):
                    res.setdefault(name.split(":")[0], []).append("/" + path)
    return res
linked = {k: sorted({libs[x] for x in v if x in libs})[:3] for k, v in owners(libs).items()}
imported = {k: sorted({pyimports[x] for x in v if x in pyimports})[:3] for k, v in owners(pyimports).items()}
own = {}   # ROS package -> {deb: example binary}; only the package's OWN executables (lib/<pkg>/*) and libraries (lib/lib<pkg>*.so*)
allpaths = {}
for p in sorted(os.listdir(SHARE)):
    files = [x for x in glob.glob(f"{LIB}/{p}/*") if os.path.isfile(x)] + glob.glob(f"{LIB}/lib{p}*.so*")
    for t in files:
        try: head = open(t, "rb").read(4)
        except Exception: continue
        if head != b"\x7fELF": continue
        out = subprocess.run(["ldd", t], capture_output=True, text=True).stdout
        for m in re.finditer(r"=>\s*(/\S+)", out):
            allpaths.setdefault(os.path.realpath(m.group(1)), set()).add((p, os.path.basename(t)))
o2 = owners(allpaths)
for deb, ps in o2.items():
    for path in ps:
        for (pkg, binary) in allpaths.get(path, ()):
            own.setdefault(pkg, {}).setdefault(deb, binary)
print(json.dumps({"own_links": own, "launched_pkgs": sorted(seen), "n_binaries": nexe, "linked": linked, "imported": imported}))
'''


def workspace_launch_seeds():
    pat = re.compile(r"package\s*=\s*['\"](\w+)['\"]|get_package_share_directory\(\s*['\"](\w+)['\"]|FindPackageShare\(\s*['\"](\w+)['\"]")
    seeds = set()
    for f in (TARGET / "robot_ws" / "src").rglob("launch/*.py"):
        for m in pat.finditer(f.read_text(errors="replace")):
            seeds.add(next(g for g in m.groups() if g))
    return sorted(seeds)


def workspace_python_imports():
    mods = set()
    for f in (TARGET / "robot_ws" / "src").rglob("*.py"):
        if f.name in ("setup.py",) or "launch" in f.parts:
            continue
        try:
            for n in ast.walk(ast.parse(f.read_text(errors="replace"))):
                if isinstance(n, ast.Import):
                    mods.update(a.name.split(".")[0] for a in n.names)
                elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                    mods.add(n.module.split(".")[0])
        except SyntaxError:
            pass
    return mods


def main():
    comps = json.loads((OUT / "components.json").read_text())
    cves = json.loads((OUT / "cves.json").read_text())
    G = nx.node_link_graph(json.loads((OUT / "graph.json").read_text()), edges="edges")
    sbom = json.loads((OUT / "sbom.cdx.json").read_text())
    prov_src = {}
    for c in sbom["components"]:
        p = c.get("purl", "")
        sup = (c.get("supplier") or {}).get("name", "")
        if p.startswith("pkg:pypi"):
            prov_src[c["name"]] = ("PyPI", p)
        elif p.startswith("pkg:deb"):
            prov_src[c["name"]] = ("ROS apt repo" if c["name"].startswith("ros-jazzy-") or "Open Robotics" in sup else "Ubuntu archive", p)

    # ---- exposure
    roots = [n for n, d in G.nodes(data=True) if d.get("layer") == "source" and d.get("kind") == "ros-package" and d["name"].startswith("turtlebot3")]
    full = set(roots)
    for r in roots:
        full |= nx.descendants(G, r)
    RG = nx.DiGraph()
    for u, v, d in G.edges(data=True):
        t = set(d.get("type", "").split(","))
        if t & {"sbom-depends", "packaged-as", "contains"} or t & RUNTIME_TAGS:
            RG.add_edge(u, v)
    rt = set(roots)
    for r in roots:
        if r in RG:
            rt |= nx.descendants(RG, r)

    # ---- reachability (ldd / imports inside the image)
    seeds = workspace_launch_seeds()
    r = subprocess.run(["docker", "run", "--rm", "-i", IMAGE, "python3", "-c", INSIDE], input=json.dumps(seeds),
                       capture_output=True, text=True, check=True)
    reach = json.loads(r.stdout)
    linked, imported = reach["linked"], reach["imported"]
    ws_mods = workspace_python_imports()
    pip_names = {c["name"].lower().replace("_", "-"): c["name"] for c in comps if c["layer"] == "pip"}
    for m in ws_mods:  # python modules imported by TurtleBot3 workspace nodes
        for cand in (m.replace("_", "-"), "python3-" + m.replace("_", "-"), "ros-jazzy-" + m.replace("_", "-")):
            if f"apt:{cand}" in G:
                imported.setdefault(cand, ["workspace python node"])
            if cand in pip_names:
                imported.setdefault(pip_names[cand], ["workspace python node"])

    keyed = {}
    for c in cves:
        pkg = c["package"]
        nid = f"apt:{pkg}" if c["layer"] == "apt" else f"pip:{pkg}"
        if nid not in full:
            expo = "base image only"
        elif BUILD_ONLY.search(pkg):
            expo = "build/dev-only"
        elif nid in rt:
            expo = "runtime"
        else:
            expo = "build/dev-only"
        evid = None
        if pkg in linked:
            evid = f"linked (ldd) by {', '.join(linked[pkg])}"
        elif pkg in imported:
            evid = f"imported by {', '.join(imported[pkg])}"
        provenance = prov_src.get(pkg, ("unknown", ""))[0]
        fix = bool(c["fixed"])
        reasons = []
        score = BASE.get(c["severity"], 2)
        reasons.append(f"severity {c['severity']}")
        if pkg == "linux-libc-dev":
            reasons.append("build-only kernel headers")
        elif expo == "build/dev-only":
            reasons.append("build/dev-only package (headers/compiler/-dev or build/test-only dependency)")
        elif expo == "base image only":
            reasons.append("in the base image but no TurtleBot3 dependency path leads to it")
        else:
            reasons.append("runtime dependency of the TurtleBot3 tree")
        score *= EXPO_MULT[expo]
        if expo != "base image only" and evid:
            score *= 1.5
            reasons.append(evid)
        elif expo == "runtime":
            score *= 0.8
            reasons.append("no linking/import evidence from launched nodes")
        score *= PROV_MULT[provenance]
        reasons.append(f"provenance: {provenance}")
        score *= 1.2 if fix else 0.8
        reasons.append(f"fix available: {c['fixed']}" if fix else "no fixed version listed")
        c.update(exposure=expo, reachability=evid or "not observed", provenance=provenance, fix_available=fix,
                 score=round(score, 1), priority_reasons=reasons,
                 in_tree=nid in full, runtime=expo == "runtime", reachable=bool(evid) and expo != "base image only")

    n_tree = sum(c["in_tree"] for c in cves)
    n_rt = sum(c["runtime"] for c in cves)
    n_reach = sum(c["runtime"] and c["reachable"] for c in cves)
    ranked = sorted(cves, key=lambda c: (-c["score"], c["id"]))
    funnel = {"total": len(cves), "in_robot_tree": n_tree, "runtime": n_rt, "reachable": n_reach, "top": 10,
              "launched_packages": reach["launched_pkgs"], "binaries_scanned": reach["n_binaries"],
              "launch_seeds": seeds}
    picked, per_pkg = [], collections.Counter()
    for c in ranked:  # at most 3 CVEs per package so the top 10 is not a single library
        if per_pkg[c["package"]] < 3:
            per_pkg[c["package"]] += 1
            picked.append(c)
        if len(picked) == 10:
            break
    top = [{k: c[k] for k in ("id", "package", "installed", "severity", "fixed", "score", "exposure", "reachability",
                              "provenance", "priority_reasons", "path")} for c in picked]
    # ROS package -> runtime CVEs in libraries that ITS OWN binaries link (ldd), only for runtime (exec/depend) packages
    SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    by_deb = collections.defaultdict(list)
    for c in cves:
        if c["runtime"]:
            by_deb[c["package"]].append(c)
    ros_amber, ros_links_all = {}, collections.defaultdict(list)
    for pkg, debs in reach["own_links"].items():
        if f"ros:{pkg}" not in rt:
            continue
        for d in debs:
            ros_links_all[d].append(pkg)
        libs = {d: {"binary": b, "cves": len(by_deb[d]), "worst": max(by_deb[d], key=lambda c: SEV.get(c["severity"], 0))["severity"]}
                for d, b in debs.items() if d in by_deb and not BASE_LIBS.match(d)}
        if libs:
            ros_amber[pkg] = libs
    (OUT / "cves.json").write_text(json.dumps(cves, indent=1))
    (OUT / "priority.json").write_text(json.dumps({"funnel": funnel, "top10": top, "ros_amber": ros_amber, "ros_links_all": ros_links_all}, indent=1))
    print(f"funnel: {len(cves)} CVEs -> {n_tree} in robot's tree -> {n_rt} runtime -> {n_reach} reachable -> top 10")
    print(f"launch seeds: {len(seeds)} pkgs; launched (recursive, in image): {len(reach['launched_pkgs'])}; binaries ldd'd: {reach['n_binaries']}; "
          f"linked debs: {len(linked)}; python-imported debs: {len(imported)}")
    for t in top:
        print(f"  {t['score']:5} {t['id']:16} {t['severity']:8} {t['package']:28} {t['exposure']:15} {t['reachability'][:50]}")
    print(f"ROS packages with runtime CVEs in libs their own binaries link: {len(ros_amber)}")
    for k in ("ament_cmake", "geometry_msgs"):
        print(" ", k, "amber" if k in ros_amber else "not amber", "| own binaries link:", len(reach["own_links"].get(k, {})), "debs")
    l = [c for c in cves if c["package"] == "linux-libc-dev"]
    if l:
        print("linux-libc-dev:", len(l), "CVEs, max score", max(c["score"] for c in l), "|", l[0]["priority_reasons"])


if __name__ == "__main__":
    main()
