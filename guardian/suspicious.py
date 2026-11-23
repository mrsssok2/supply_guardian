#!/usr/bin/env python3
"""STEP 3 - detect suspicious supply-chain changes between two branches of target/.

Usage: suspicious.py [BASE=main] [HEAD=planted]
Writes out/changes.json (all hunks) and out/findings.json, then scores against GROUND_TRUTH.json.
Detection only - nothing is executed; setup.py files are parsed with ast, never imported.
"""
import ast, base64, binascii, difflib, json, os, re, shutil, subprocess, sys, collections
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


# ------------------------------------------------------------------ behaviour analysis (text only, nothing is executed)
B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
HEXRE = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")
BIN_MAGIC = {b"\x89PNG": "PNG image", b"GIF8": "GIF image", b"\xff\xd8\xff": "JPEG image", b"\x7fELF": "ELF binary",
             b"PK\x03\x04": "ZIP archive", b"%PDF": "PDF document"}
CRED_RE = re.compile(r"~/\.ssh|\.ssh/id_|id_rsa|\.npmrc|\.netrc|\.aws/credentials|\.docker/config\.json|"
                     r"(os\.environ|getenv)[^\n]{0,60}(AWS_|TOKEN|SECRET|PASSWORD|API_?KEY)")
NET_RE = re.compile(r"(requests|httpx)\.(post|put)\s*\(|urlopen\([^)]*data\s*=|method\s*=\s*['\"]POST['\"]|socket\.(socket|create_connection)")
URL_RE = re.compile(r"https?://[^\s\"')]+")
DLEX_RE = re.compile(r"(curl|wget)\b[^\n]*https?://\S+[^\n]*(chmod\s+\+x|\|\s*(ba|z)?sh\b|&&\s*[./]|;\s*[./])")
EXEC_RE = re.compile(r"\b(exec|eval|compile)\s*\(")


def decode_blobs(line):
    """base64 / hex strings in a source line -> [{encoding, encoded, kind: text|binary|noise, text}] (decode only, never run)."""
    out = []
    cands = [("base64", m.group(0)) for m in B64.finditer(line)] + [("hex", m.group(0)) for m in HEXRE.finditer(line)]
    for enc, tok in cands:
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True) if enc == "base64" else bytes.fromhex(tok)
        except (binascii.Error, ValueError):
            continue
        magic = next((v for k, v in BIN_MAGIC.items() if raw.startswith(k)), None)
        if magic:
            out.append({"encoding": enc, "encoded": tok, "kind": f"binary ({magic})", "text": ""})
            continue
        try:
            txt = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(c.isprintable() or c in "\n\t\r" for c in txt)
        if len(txt) >= 12 and printable / len(txt) >= 0.95:
            out.append({"encoding": enc, "encoded": tok, "kind": "text", "text": txt})
    return out


def behaviour_scan(by_file, add, pkg_name_of, show):
    for f, cs in sorted(by_file.items()):
        if not f.endswith((".py", ".sh")) or cs[0]["status"] == "deleted":
            continue
        src = show(f)
        lines = src.splitlines()
        comp = pkg_name_of(os.path.dirname(f) + "/package.xml") or os.path.basename(os.path.dirname(f))
        seen = set()

        def emit(type_, line_no, encoded, decoded, evidence, risk, reason):
            if (type_, line_no) in seen:
                return
            seen.add((type_, line_no))
            add(type_, comp, "source", f, line_no, None, (encoded or lines[line_no - 1]).strip()[:120], evidence, risk, reason,
                encoded=(lines[line_no - 1].strip() if encoded else None), decoded=decoded)

        for i, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue
            # plain-text behaviour
            if CRED_RE.search(line):
                emit("credential_access", i, None, None, f"{f}:{i} touches credentials: {line.strip()}", "critical",
                     "code reads SSH keys / cloud credentials / secret environment variables")
            if NET_RE.search(line) and URL_RE.search(line):
                emit("network_exfiltration", i, None, None, f"{f}:{i} sends data to {URL_RE.search(line).group(0)}: {line.strip()}", "high",
                     "code POSTs data to a remote URL")
            if DLEX_RE.search(line):
                emit("download_and_execute", i, None, None, f"{f}:{i} downloads and runs a remote program: {line.strip()}", "critical",
                     "downloads a binary from a URL, makes it executable and runs it (miner-style dropper)")
            # encoded payloads
            for b in decode_blobs(line):
                if b["kind"] != "text":
                    continue  # e.g. a base64 PNG icon: binary media, not code
                txt = b["text"]
                snippet = txt.strip().replace("\r", "")[:500]
                near = "\n".join(lines[max(0, i - 4): i + 3])
                hits = []
                if CRED_RE.search(txt):
                    hits.append("credential_access")
                    emit("credential_access", i, b["encoded"], snippet,
                         f"{f}:{i} ENCODED ({b['encoding']}): {line.strip()}\nDECODED: {snippet}", "critical",
                         "decoded payload reads SSH keys / cloud credentials / secret environment variables")
                if NET_RE.search(txt) and URL_RE.search(txt):
                    hits.append("network_exfiltration")
                    emit("network_exfiltration", i, b["encoded"], snippet,
                         f"{f}:{i} ENCODED ({b['encoding']}): {line.strip()}\nDECODED: {snippet}", "critical" if "credential_access" in hits else "high",
                         f"decoded payload POSTs data to {URL_RE.search(txt).group(0)}")
                if DLEX_RE.search(txt):
                    hits.append("download_and_execute")
                    emit("download_and_execute", i, b["encoded"], snippet,
                         f"{f}:{i} ENCODED ({b['encoding']}): {line.strip()}\nDECODED: {snippet}", "critical", "decoded payload downloads and runs a program")
                if hits or EXEC_RE.search(near) or re.search(r"\bimport\s+\w+|\bdef\s+\w+\(", txt):
                    emit("obfuscated_payload", i, b["encoded"], snippet,
                         f"{f}:{i} ENCODED ({b['encoding']}): {line.strip()}\nDECODED: {snippet}\n(decoded text flagged: {', '.join(hits) or 'code passed to exec/eval'})",
                         "critical" if hits else "high", "hides code in a base64/hex string that is decoded at install time (obfuscation)")


# ------------------------------------------------------------------ antivirus (ClamAV via Docker, fallback: EICAR signature string)
CLAM_IMAGE = os.environ.get("CLAM_IMAGE", "clamav/clamav:stable")
CLAM_DB_VOL = "guardian_clamdb"


def antivirus_scan():
    """Extract branch HEAD into out/planted_ws, generate the EICAR test file there (scan time), scan with ClamAV.
    Returns (hits[(relpath, signature)], info dict)."""
    ws = OUT / "planted_ws"
    shutil.rmtree(ws, ignore_errors=True)
    ws.mkdir(parents=True)
    arch = subprocess.run(["git", "-C", str(TARGET), "archive", HEAD], capture_output=True, check=True).stdout
    subprocess.run(["tar", "-x", "-C", str(ws)], input=arch, check=True)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import make_eicar
    make_eicar.main(str(ws))
    info = {"engine": "clamav", "image": CLAM_IMAGE, "note": ""}

    def clam(args, timeout):
        return subprocess.run(["docker", "run", "--rm", "-v", f"{ws}:/scan:ro", "-v", f"{CLAM_DB_VOL}:/var/lib/clamav",
                               "--entrypoint", args[0], CLAM_IMAGE, *args[1:]], capture_output=True, text=True, timeout=timeout)
    try:
        r = clam(["clamscan", "-r", "--infected", "--no-summary", "/scan"], 600)
        if "No supported database files" in (r.stdout + r.stderr) or r.returncode == 2:
            fr = subprocess.run(["docker", "run", "--rm", "-v", f"{CLAM_DB_VOL}:/var/lib/clamav", "--entrypoint", "freshclam", CLAM_IMAGE],
                                capture_output=True, text=True, timeout=300)
            info["freshclam"] = (fr.stdout + fr.stderr)[-300:]
            r = clam(["clamscan", "-r", "--infected", "--no-summary", "/scan"], 600)
            if r.returncode == 2:
                raise RuntimeError((r.stdout + r.stderr)[-300:])
        hits = [(m.group(1), m.group(2)) for m in re.finditer(r"^/scan/(.+?): (\S+) FOUND$", r.stdout, re.M)]
        v = clam(["clamscan", "--version"], 60).stdout.strip()
        info["version"] = v
        return hits, info
    except Exception as e:  # ClamAV unavailable / signature download failed or timed out -> standard EICAR string match
        import make_eicar as me
        hits = []
        for p in ws.rglob("*"):
            if p.is_file() and p.stat().st_size < 1_000_000:
                try:
                    if me.EICAR in p.read_text(errors="ignore"):
                        hits.append((str(p.relative_to(ws)), "Eicar-Test-Signature (string match)"))
                except OSError:
                    pass
        info.update(engine="signature-string fallback (ClamAV unavailable)", note=f"{type(e).__name__}: {e}"[:300])
        return hits, info


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
    behaviour_scan(by_file, add, pkg_name_of, show)
    hits, av = antivirus_scan()
    (OUT / "av.json").write_text(json.dumps(av, indent=1))
    for rel, sig in hits:
        add("antivirus_hit", sig, "source", rel, 0, None, sig, f"{av['engine']}: {rel}: {sig} FOUND (scan of the planted workspace extracted to out/planted_ws)",
            "high", "antivirus signature match (EICAR is the standard harmless AV test file)")
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
