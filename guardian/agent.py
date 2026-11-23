#!/usr/bin/env python3
"""STEP 3/5 - Investigator agent (local Ollama only, read-only tools).

For each critical/high suspicious finding the model may call up to 5 tools
(read_file, git_diff, dependency_path, scan_setup_py), then must return
{verdict: malicious|suspicious|benign, reasons[], confidence}.
Grounding check: every file / number / package-like token in the reasons must appear in the
finding header or a tool result, otherwise the answer is rejected and a deterministic template
is used.  Hygiene-only finding types (unpinned/branch/tag pins) are capped at 'suspicious'.
Output: out/agent.json (tool calls + verdict per finding).
"""
import json, os, re, subprocess, sys, urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import suspicious as S  # reuse analyse_setup_py (ast based, never executes code)

ROOT = S.ROOT
TARGET, OUT = S.TARGET, S.OUT
OLLAMA = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11435")
VERDICTS = ("malicious", "suspicious", "benign")
HYGIENE = {"branch_pinned_repo", "unpinned_base_image", "tag_pinned_action"}
MAX_CALLS = 5

TOOLS_HELP = """Tools (reply with JSON only):
 {"tool":"read_file","args":{"path":"<repo-relative path>","start":1,"end":60}}  - read lines of a file on branch planted
 {"tool":"git_diff","args":{"file":"<repo-relative path>"}}                     - diff main..planted for one file
 {"tool":"dependency_path","args":{"component":"<package name>"}}                - dependency path from the turtlebot3 packages
 {"tool":"scan_setup_py","args":{"path":"<path to setup.py>"}}                   - AST scan for install-time file writes/subprocess/network/eval
When you have enough facts reply with the final answer:
 {"verdict":"malicious|suspicious|benign","reasons":["<reason 1>","<reason 2>"],"confidence":"low|medium|high"}
Replace the <reason> placeholders with real reasons. Rules: use ONLY facts returned by tools. Do not mention any file, line, number or package that no tool returned.
'malicious' needs evidence of code that executes or changes behaviour; supply-chain hygiene problems (unpinned refs) alone are 'suspicious'."""


# ------------------------------------------------------------------ tools (read-only)
def _safe_rel(p):
    p = str(p).strip().lstrip("/")
    if ".." in Path(p).parts or not p:
        raise ValueError("path must be repo-relative")
    return p


def t_read_file(path, start=1, end=60):
    path = _safe_rel(path)
    start, end = max(int(start), 1), min(int(end), int(start) + 79)
    txt = S.git("show", f"planted:{path}")
    if not txt:
        return f"file not found on branch planted: {path}"
    lines = txt.splitlines()[start - 1:end]
    return "\n".join(f"{path}:{start + i}: {l}" for i, l in enumerate(lines))


def t_git_diff(file):
    d = S.git("diff", "--no-renames", "--unified=0", "main", "planted", "--", _safe_rel(file))
    return d[:2500] or "no diff for that file"


def t_dependency_path(component, finding=None):
    import networkx as nx
    G = nx.node_link_graph(json.loads((OUT / "graph.json").read_text()), edges="edges")
    if finding and finding.get("dep_path"):
        dp = finding["dep_path"]
        if component == dp[-1]:
            return f"{' -> '.join(dp)} (new edge added on branch planted; '{component}' is not in the main graph)"
    names = {d["name"]: n for n, d in G.nodes(data=True)}
    if component not in names:
        return f"'{component}' not found in the main dependency graph"
    roots = [n for n, d in G.nodes(data=True) if d.get("layer") == "source" and d.get("kind") == "ros-package" and d["name"].startswith("turtlebot3")]
    best = None
    for r in roots:
        try:
            p = nx.shortest_path(G, r, names[component])
            best = p if best is None or len(p) < len(best) else best
        except nx.NetworkXNoPath:
            pass
    return " -> ".join(G.nodes[x]["name"] for x in best) if best else f"no path from turtlebot3 packages to '{component}'"


def t_scan_setup_py(path):
    path = _safe_rel(path)
    src = S.git("show", f"planted:{path}")
    if not src:
        return f"file not found on branch planted: {path}"
    hits, hooked = S.analyse_setup_py(src)
    if not hits:
        return f"{path}: no file writes, subprocess, network or eval found; install hook overridden: {hooked}"
    return "\n".join(f"{path}:{ln} [{k}] {t}" for ln, k, t in hits) + f"\ninstall hook (cmdclass) overridden: {hooked}"


def run_tool(name, args, finding):
    try:
        if name == "read_file":
            return t_read_file(**{k: v for k, v in args.items() if k in ("path", "start", "end")})
        if name == "git_diff":
            return t_git_diff(args.get("file") or args.get("path"))
        if name == "dependency_path":
            return t_dependency_path(args.get("component") or args.get("name"), finding)
        if name == "scan_setup_py":
            return t_scan_setup_py(args.get("path") or args.get("file"))
        return f"unknown tool {name!r}"
    except Exception as e:
        return f"tool error: {type(e).__name__}: {e}"


# ------------------------------------------------------------------ model
def pick_model():
    base = OLLAMA.rstrip("/")
    names = [m["name"] for m in json.load(urllib.request.urlopen(base + "/api/tags", timeout=5)).get("models", [])]
    if not names:
        raise RuntimeError("no model installed")
    return os.environ.get("OLLAMA_MODEL") or next((n for n in names if n.startswith("qwen3:1.7b")), names[0])


def chat(model, messages):
    req = urllib.request.Request(OLLAMA.rstrip("/") + "/api/chat", method="POST",
                                 headers={"Content-Type": "application/json"},
                                 data=json.dumps({"model": model, "messages": messages, "stream": False, "think": False,
                                                  "format": "json", "options": {"temperature": 0}}).encode())
    return json.load(urllib.request.urlopen(req, timeout=120))["message"]["content"]


def ungrounded(text, facts):
    low = facts.lower()
    bad = []
    for tok in set(re.findall(r"[\w./@-]+\.(?:py|xml|yml|yaml|repos|cfg|txt|sh)\b|\b[\w-]*Dockerfile\b", text)):
        if tok.lower() not in low:
            bad.append(tok)
    for tok in set(re.findall(r"\b\d+(?:\.\d+)*\b", text)):
        if tok not in facts:
            bad.append(tok)
    for tok in set(re.findall(r"\b[a-z0-9]+(?:_[a-z0-9]+)+\b|\b[a-z0-9-]+/[a-z0-9._-]+\b", text)):
        if tok.lower() not in low:
            bad.append(tok)
    return sorted(set(bad))


def template(f):
    t = {
        "install_time_code": ("malicious", "The new package runs file-writing code when it is installed"),
        "unexpected_dependency": ("suspicious", "An existing robot package gained a dependency that is not in the known inventory"),
        "curl_pipe_bash": ("malicious", "The build downloads a remote script and runs it in a shell without review"),
        "unofficial_apt_source": ("suspicious", "The image adds a non-official apt source with signature checking disabled"),
        "typosquat_name": ("suspicious", "The package name imitates an official package family but is not one"),
        "branch_pinned_repo": ("suspicious", "A source dependency follows a moving branch instead of a fixed commit"),
        "unpinned_base_image": ("suspicious", "The base image has no content digest, so it can change silently"),
        "tag_pinned_action": ("suspicious", "A CI action is pinned to a mutable tag instead of a commit SHA"),
    }.get(f["type"], ("suspicious", "The change matches a supply-chain risk rule"))
    return t[0], [f"{t[1]} (rule-based template; evidence is {f['file']} line {f['line']})."], "low"


def investigate(f, model):
    header = f"FINDING {f['id']}: type={f['type']} risk={f['risk']} file={f['file']} line={f['line']} component={f['component']}"
    facts = [header]
    calls = []
    msgs = [{"role": "system", "content": "You are a supply-chain security investigator for a ROS 2 robot repository.\n" + TOOLS_HELP},
            {"role": "user", "content": header + "\nInvestigate with tools, then give your verdict."}]
    final = None
    for step in range(MAX_CALLS + 1):
        raw = chat(model, msgs)
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            obj = {}
        if "verdict" in obj:
            final = obj
            break
        if step == MAX_CALLS or "tool" not in obj:
            msgs += [{"role": "assistant", "content": raw},
                     {"role": "user", "content": "Give the final JSON answer now (verdict, reasons, confidence)."}]
            raw = chat(model, msgs)
            try:
                final = json.loads(raw)
            except json.JSONDecodeError:
                final = None
            break
        res = run_tool(obj["tool"], obj.get("args") or {}, f)
        calls.append({"tool": obj["tool"], "args": obj.get("args") or {}, "result": res[:1500]})
        facts.append(res)
        msgs += [{"role": "assistant", "content": raw}, {"role": "user", "content": "TOOL RESULT:\n" + res[:2500]}]
    return final, calls, "\n".join(facts)


def main():
    findings = json.loads((OUT / "findings.json").read_text())
    result = {}
    try:
        model = pick_model()
    except Exception as e:
        model, why = None, f"ollama unavailable ({type(e).__name__})"
    for f in findings:
        if f["risk"] not in ("critical", "high"):
            continue
        v, reasons, conf = template(f)
        entry = {"verdict": v, "reasons": reasons, "confidence": conf, "tool_calls": [], "source": "template", "note": ""}
        if model:
            try:
                final, calls, facts = investigate(f, model)
                entry["tool_calls"] = calls
                fv = str((final or {}).get("verdict", "")).lower()
                rs = (final or {}).get("reasons") or []
                rs = [rs] if isinstance(rs, str) else [str(x) for x in rs]
                bad = ungrounded(" ".join(rs), facts)
                if fv in VERDICTS and rs and not bad:
                    entry.update(verdict=fv, reasons=rs[:3], confidence=str((final or {}).get("confidence", "low")).lower(),
                                 source=f"ollama:{model} (grounding check passed)")
                    if fv == "malicious" and f["type"] in HYGIENE:
                        entry.update(verdict="suspicious", note="capped: unpinned/branch/tag pins are hygiene risks, not proof of malice")
                else:
                    entry["note"] = f"model answer rejected: verdict={fv!r} ungrounded={bad}"
            except Exception as e:
                entry["note"] = f"investigation failed ({type(e).__name__}: {e}); template used"
        else:
            entry["note"] = why
        entry["verdict_text"] = f"{entry['verdict'].capitalize()} (confidence {entry['confidence']}): " + " ".join(entry["reasons"])
        result[f["id"]] = entry
        print(f["id"], f["type"], "->", entry["verdict"], "|", entry["source"], f"| {len(entry['tool_calls'])} tool calls", entry["note"])
    (OUT / "agent.json").write_text(json.dumps(result, indent=1))
    g = sum(e["source"].startswith("ollama") for e in result.values())
    print(f"grounded model verdicts: {g}, template fallbacks: {len(result) - g}")


if __name__ == "__main__":
    main()
