#!/usr/bin/env python3
"""STEP 3 - detect suspicious supply-chain changes between two branches of target/.

Usage: suspicious.py [BASE=main] [HEAD=planted]
Writes out/changes.json (all hunks) and out/findings.json, then scores against GROUND_TRUTH.json.
Detection only - nothing is executed; setup.py files are parsed with ast, never imported.
"""
import ast, difflib, json, os, re, subprocess, sys, collections
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = Path(os.environ.get("TARGET_DIR", ROOT / "target"))
OUT = ROOT / "out"
BASE = sys.argv[1] if len(sys.argv) > 1 else "main"
HEAD = sys.argv[2] if len(sys.argv) > 2 else "planted"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
OFFICIAL_APT_HOSTS = ("archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com", "packages.ros.org",
                      "repo.ros2.org", "packages.osrfoundation.org", "deb.debian.org")


def git(*a):
    return subprocess.run(["git", "-C", str(TARGET), *a], check=True, capture_output=True, text=True).stdout


# ------------------------------------------------------------------ diff parsing
def parse_diff():
    """-> list of change dicts: file, line (new-side), old, new, status."""
    raw = git("diff", "--no-renames", "--unified=0", BASE, HEAD)
    changes, f, status = [], None, "modified"
    old_l = new_l = 0
    rem, add = [], []

    def flush():
        nonlocal rem, add
        if f and (rem or add):
            n = max(len(rem), len(add))
            for i in range(n):
                o = rem[i] if i < len(rem) else None
                nw = add[i] if i < len(add) else None
                changes.append({"file": f, "status": status,
                                "line": nw[0] if nw else (o[0] if o else 0),
                                "old": o[1] if o else None, "new": nw[1] if nw else None})
        rem, add = [], []

    for line in raw.splitlines():
        if line.startswith("diff --git"):
            flush()
            f, status = None, "modified"
        elif line.startswith("new file"):
            status = "added"
        elif line.startswith("deleted file"):
            status = "deleted"
        elif line.startswith("+++ "):
            p = line[4:]
            f = p[2:] if p.startswith("b/") else f
        elif line.startswith("--- "):
            p = line[4:]
            if p.startswith("a/"):
                f = p[2:]
        elif line.startswith("@@"):
            flush()
            m = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
            old_l, new_l = int(m.group(1)), int(m.group(2))
        elif line.startswith("-") and f:
            rem.append((old_l, line[1:])); old_l += 1
        elif line.startswith("+") and f:
            add.append((new_l, line[1:])); new_l += 1
    flush()
    return changes


def show(path):
    try:
        return git("show", f"{HEAD}:{path}")
    except subprocess.CalledProcessError:
        return ""


# ------------------------------------------------------------------ known names
def known_names():
    comps = json.loads((OUT / "components.json").read_text())
    ros = {c["name"] for c in comps if c["layer"] in ("ros", "source")}
    other = {c["name"] for c in comps if c["layer"] in ("apt", "pip")}
    return ros, other


def pkg_name_of(pkgxml_path):
    m = re.search(r"<name>\s*([^<\s]+)\s*</name>", show(pkgxml_path))
    return m.group(1) if m else None


# ------------------------------------------------------------------ setup.py analysis
RISKY_CALLS = {
    "os.system": "runs shell command", "os.popen": "runs shell command", "eval": "eval", "exec": "exec",
    "compile": "dynamic compile", "__import__": "dynamic import",
}


def dotted(n):
    if isinstance(n, ast.Attribute):
        d = dotted(n.value)
        return f"{d}.{n.attr}" if d else n.attr
    return n.id if isinstance(n, ast.Name) else ""


def analyse_setup_py(src):
    """Return list of (line, kind, text) of install-time-capable risky operations + whether install hooked."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return [], False
    lines = src.splitlines()
    hits, hooked = [], False
    for n in ast.walk(tree):
        if isinstance(n, ast.keyword) and n.arg == "cmdclass":
            hooked = True
        if isinstance(n, ast.Call):
            name = dotted(n.func)
            kind = None
            if name == "open":
                mode = ""
                if len(n.args) > 1 and isinstance(n.args[1], ast.Constant):
                    mode = str(n.args[1].value)
                for k in n.keywords:
                    if k.arg == "mode" and isinstance(k.value, ast.Constant):
                        mode = str(k.value.value)
                if any(c in mode for c in "wax+"):
                    kind = "file write"
            elif name in RISKY_CALLS:
                kind = RISKY_CALLS[name]
            elif name.startswith("subprocess.") or name.split(".")[0] in ("requests", "urllib", "socket", "httpx") \
                    or name.endswith(("urlopen", "urlretrieve")):
                kind = "subprocess" if name.startswith("subprocess.") else "network"
            elif name.endswith((".write_text", ".write_bytes", "shutil.copy", "shutil.copyfile", "os.remove", "os.unlink")):
                kind = "file write"
            if kind:
                hits.append((n.lineno, kind, lines[n.lineno - 1].strip()))
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in n.names] + ([n.module] if isinstance(n, ast.ImportFrom) and n.module else [])
            for m in mods:
                if m.split(".")[0] in ("subprocess", "socket", "urllib", "requests", "http", "ftplib") \
                        and not any(h[0] == n.lineno for h in hits):
                    hits.append((n.lineno, "imports " + m, lines[n.lineno - 1].strip()))
    hits.sort()
    return hits, hooked


OFFICIAL_PREFIXES = ("nav2_", "ros_", "rclpy", "turtlebot3_")


def edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def typosquat_reason(name, official):
    """None, or why `name` (not an official package) looks like a typosquat: edit distance <= 2 of a real
    package name, or an official prefix (nav2_, ros_, rclpy, turtlebot3_) without being in the official list."""
    if name in official:
        return None
    near = sorted((edit_distance(name, o), o) for o in official if abs(len(o) - len(name)) <= 2)[:3]
    if near and near[0][0] <= 2:
        return (f"'{name}' is not an official package but is within edit distance {near[0][0]} of real package "
                f"'{near[0][1]}'")
    for pre in OFFICIAL_PREFIXES:
        if name.startswith(pre):
            return f"'{name}' uses the official prefix '{pre}' but is not in the official package list (image ROS packages + workspace on main)"
    return None


# ------------------------------------------------------------------ detection
def detect(changes):
    ros_names, other_names = known_names()
    all_known = ros_names | other_names
    # packages present in BASE workspace = baseline; new ones live only in HEAD
    findings = []
    seq = 0

    def add(type_, component, layer, file, line, old, new, evidence, risk, reason, **extra):
        nonlocal seq
        seq += 1
        findings.append({"id": f"F{seq:03d}", "type": type_, "component": component, "layer": layer,
                         "file": file, "line": line, "old": old, "new": new, "evidence": evidence,
                         "risk": risk, "reason": reason, **extra})

    by_file = collections.defaultdict(list)
    for c in changes:
        by_file[c["file"]].append(c)

    # ---- new packages: typosquat names + install-time code
    new_pkgs = {}
    for f, cs in by_file.items():
        if f.endswith("package.xml") and cs[0]["status"] == "added":
            n = pkg_name_of(f)
            if n:
                new_pkgs[n] = f
    risky_new = {}
    for name, pf in new_pkgs.items():
        d = os.path.dirname(pf)
        sp = f"{d}/setup.py"
        if sp in by_file:
            hits, hooked = analyse_setup_py(show(sp))
            if hits:
                risky_new[name] = sp
                kinds = sorted({h[1] for h in hits})
                ev = "; ".join(f"{sp}:{ln} [{k}] {txt}" for ln, k, txt in hits)
                if hooked:
                    ev += f"; setup.py overrides cmdclass (code runs at pip/colcon install time)"
                risk = "critical" if hooked and any(not k.startswith("imports") for k in kinds) else "high"
                add("install_time_code", name, "source", sp, hits[0][0], None, f"{len(hits)} risky operation(s): {', '.join(kinds)}",
                    ev, risk, "new package runs file-writing/subprocess/network/eval code when installed", hits=[list(h) for h in hits], hooked=hooked)
        # typosquat-like name
        why = typosquat_reason(name, ros_names)
        if why:
            add("typosquat_name", name, "source", pf, 1, None, name, why, "high",
                "name imitates a real/official ROS package name but is not one in the image or workspace")

    # ---- changes in package.xml of existing packages: new dependency
    dep_re = re.compile(r"<(depend|build_depend|exec_depend|test_depend|build_export_depend|buildtool_depend)>\s*([^<\s]+)\s*</")
    for f, cs in by_file.items():
        if not f.endswith("package.xml") or cs[0]["status"] == "added":
            continue
        owner = pkg_name_of(f)
        for c in cs:
            m = dep_re.search(c["new"] or "")
            if not m:
                continue
            dep = m.group(2)
            if dep in all_known:
                continue
            path = f"{owner} -> {dep}"
            extra = ""
            risk = "high"
            if dep in risky_new:
                risk = "critical"
                extra = f"; '{dep}' contains install-time code ({risky_new[dep]})"
            why = typosquat_reason(dep, ros_names) if dep not in new_pkgs else None
            if why:
                add("typosquat_name", dep, "ros", f, c["line"], c["old"], c["new"].strip(), why, "high",
                    "dependency name imitates a real/official ROS package name but is not one")
            add("unexpected_dependency", dep, "ros", f, c["line"], c["old"], c["new"].strip(),
                f"{f}:{c['line']} adds <{m.group(1)}>{dep}</...> to {owner}; '{dep}' is not in the upstream ROS install, "
                f"apt or pip inventory{extra}. Dependency path: {path}",
                risk, "robot package gained a dependency that is not part of the known software inventory",
                dep_path=[owner, dep])

    # ---- robot.repos: branch pins
    for c in by_file.get("robot.repos", []):
        m = re.match(r"\s*version:\s*(\S+)", c["new"] or "")
        if m and not HEX40.match(m.group(1)):
            om = re.match(r"\s*version:\s*(\S+)", c["old"] or "")
            repo = ""
            for ln in reversed(show("robot.repos").splitlines()[: c["line"]]):
                mm = re.match(r"^  (\S+):\s*$", ln)
                if mm:
                    repo = mm.group(1); break
            add("branch_pinned_repo", repo, "source", "robot.repos", c["line"], c["old"].strip() if c["old"] else None,
                c["new"].strip(), f"robot.repos:{c['line']} {repo} version '{m.group(1)}' is a moving ref, not a 40-char commit"
                + (f" (was commit {om.group(1)[:12]})" if om and HEX40.match(om.group(1)) else ""),
                "high", "source dependency can change silently; build is not reproducible")

    # ---- Dockerfile
    for c in by_file.get("Dockerfile", []):
        nw = c["new"] or ""
        m = re.match(r"\s*FROM\s+(\S+)", nw, re.I)
        if m and "@sha256:" not in m.group(1):
            was = bool(c["old"] and "@sha256:" in c["old"])
            add("unpinned_base_image", m.group(1), "image", "Dockerfile", c["line"], (c["old"] or "").strip() or None, nw.strip(),
                f"Dockerfile:{c['line']} base image '{m.group(1)}' has no @sha256 digest" + (" (digest was removed)" if was else ""),
                "high" if was else "medium", "base image tag can be re-pointed; image contents are not reproducible")
        if re.search(r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b", nw):
            add("curl_pipe_bash", "curl|bash", "image", "Dockerfile", c["line"], None, nw.strip(),
                f"Dockerfile:{c['line']} downloads a script and pipes it straight into a shell: {nw.strip()}",
                "critical", "unreviewed remote code executes as root during image build")
        if re.search(r"sources\.list|add-apt-repository|\[trusted=yes\]|^\s*RUN .*\bdeb\s+(\[|https?://)", nw):
            hosts = re.findall(r"https?://([^/\s\"']+)", nw)
            if "trusted=yes" in nw or any(not h.endswith(OFFICIAL_APT_HOSTS) for h in hosts):
                add("unofficial_apt_source", ",".join(hosts) or "apt source", "apt", "Dockerfile", c["line"], None, nw.strip(),
                    f"Dockerfile:{c['line']} adds apt source {', '.join(hosts) or '?'}"
                    + (" with [trusted=yes] (signature checks disabled)" if "trusted=yes" in nw else ""),
                    "critical" if "trusted=yes" in nw else "high",
                    "packages from a non-official repository would be installed, possibly unsigned")

    # ---- GitHub workflows
    for f, cs in by_file.items():
        if not f.startswith(".github/workflows/"):
            continue
        for c in cs:
            m = re.search(r"uses:\s*([^\s@#]+)@([^\s#]+)", c["new"] or "")
            if m and not HEX40.match(m.group(2)) and not m.group(1).startswith("./"):
                add("tag_pinned_action", f"{m.group(1)}@{m.group(2)}", "ci", f, c["line"], (c["old"] or "").strip() or None,
                    c["new"].strip(), f"{f}:{c['line']} action {m.group(1)} pinned to mutable ref '{m.group(2)}' instead of a commit SHA",
                    "medium", "a tag can be moved to malicious code; pin to a full commit SHA")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: (order[x["risk"]], x["id"]))
    return findings


# ------------------------------------------------------------------ scoring
def score(findings):
    gt_path = ROOT / "GROUND_TRUTH.json"
    if not gt_path.exists():
        return None
    gt = json.loads(gt_path.read_text())
    found, missed, matched_ids = [], [], set()
    for p in gt["planted"]:
        got = {t: [f["id"] for f in findings if f["type"] == t and f["file"] in p["files"]] for t in p["required_types"]}
        if all(got.values()):
            found.append(p["id"])
        else:
            missed.append(p["id"])
        for f in findings:
            if f["file"] in p["files"] and f["type"] in p["required_types"] + p.get("allowed_extra_types", []):
                matched_ids.add(f["id"])
    false_alarms = [f["id"] for f in findings if f["id"] not in matched_ids]
    decoy_hits = [f["id"] for f in findings for d in gt.get("decoys_must_not_be_flagged", []) if f["file"] in d["files"]]
    return {"found": found, "missed": missed, "false_alarms": false_alarms, "decoy_flagged": decoy_hits,
            "planted_total": len(gt["planted"])}


def main():
    changes = parse_diff()
    findings = detect(changes)
    OUT.mkdir(exist_ok=True)
    (OUT / "changes.json").write_text(json.dumps(changes, indent=1))
    (OUT / "findings.json").write_text(json.dumps(findings, indent=1))
    s = score(findings)
    if s:
        (OUT / "score.json").write_text(json.dumps(s, indent=1))
    print(f"{len(changes)} changed lines, {len(findings)} findings ({BASE}..{HEAD})")
    for f in findings:
        print(f"  {f['id']} [{f['risk']:8}] {f['type']:22} {f['file']}:{f['line']}  {f['component']}")
    if s:
        print(f"FOUND {len(s['found'])}/{s['planted_total']}: {s['found']}  MISSED: {s['missed']}  "
              f"FALSE ALARMS: {len(s['false_alarms'])} {s['false_alarms']}  decoy flagged: {s['decoy_flagged']}")


if __name__ == "__main__":
    main()
