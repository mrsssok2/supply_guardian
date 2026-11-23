#!/usr/bin/env python3
"""STEP 5 - grounded AI verdicts for critical/high suspicious findings (local Ollama only).

For each finding: gather tool results (setup.py lines, git diff, dependency path), ask the local
model for a 2-sentence verdict using ONLY those results, then run a grounding check: any file,
line number, number or package-like token in the answer that is not in the tool results ->
reject and fall back to a deterministic template. Output: out/agent.json
"""
import json, os, re, subprocess, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = Path(os.environ.get("TARGET_DIR", ROOT / "target"))
OUT = ROOT / "out"
OLLAMA = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11435")
VERDICTS = ("malicious", "suspicious", "benign")


def git(*a):
    return subprocess.run(["git", "-C", str(TARGET), *a], capture_output=True, text=True).stdout


def tool_results(f):
    """Facts only: the finding's own tool output, the git diff of its file, the dependency path."""
    parts = [f"FINDING: type={f['type']} file={f['file']} line={f['line']} component={f['component']}",
             f"DETECTOR EVIDENCE: {f['evidence']}"]
    if f.get("hits"):
        parts.append("SETUP.PY LINES:\n" + "\n".join(f"{f['file']}:{ln} [{k}] {t}" for ln, k, t in f["hits"]))
    if f.get("dep_path"):
        parts.append("DEPENDENCY PATH: " + " -> ".join(f["dep_path"]))
    d = git("diff", "--no-renames", "--unified=0", "main", "planted", "--", f["file"])
    parts.append("GIT DIFF main..planted:\n" + d[:2500])
    return "\n".join(parts)


def template(f):
    t = {
        "install_time_code": ("malicious", "The new package runs file-writing code when it is installed, which a normal helper package has no need to do"),
        "unexpected_dependency": ("suspicious", "An existing robot package gained a dependency that is not in the known software inventory"),
        "curl_pipe_bash": ("malicious", "The build downloads a remote script and runs it in a shell without review"),
        "unofficial_apt_source": ("suspicious", "The image adds a non-official apt source with signature checking disabled"),
        "typosquat_name": ("suspicious", "The package name imitates an official package family but is not one"),
        "branch_pinned_repo": ("suspicious", "A source dependency follows a moving branch instead of a fixed commit"),
        "unpinned_base_image": ("suspicious", "The base image no longer has a content digest, so it can change silently"),
        "tag_pinned_action": ("suspicious", "A CI action is pinned to a mutable tag instead of a commit SHA"),
    }.get(f["type"], ("suspicious", "The change matches a supply-chain risk rule"))
    v, why = t
    return v, f"{v.capitalize()}: {why}. Evidence is {f['file']} line {f['line']}."


def ask_model(prompt):
    base = OLLAMA.rstrip("/")
    tags = json.load(urllib.request.urlopen(base + "/api/tags", timeout=5)).get("models", [])
    if not tags:
        raise RuntimeError("no model installed")
    model = os.environ.get("OLLAMA_MODEL") or tags[0]["name"]
    req = urllib.request.Request(base + "/api/generate", method="POST",
                                 headers={"Content-Type": "application/json"},
                                 data=json.dumps({"model": model, "prompt": prompt, "stream": False,
                                                  "options": {"temperature": 0}}).encode())
    return model, json.load(urllib.request.urlopen(req, timeout=120))["response"].strip()


def ungrounded(answer, facts):
    """Return tokens in the answer (files, numbers, package-like names) absent from the tool results."""
    low = facts.lower()
    bad = []
    for tok in set(re.findall(r"[\w./@-]+\.(?:py|xml|yml|yaml|repos|cfg|txt|sh)\b|\b[\w-]*Dockerfile\b", answer)):
        if tok.lower() not in low:
            bad.append(tok)
    for tok in set(re.findall(r"\b\d+(?:\.\d+)*\b", answer)):
        if tok not in facts:
            bad.append(tok)
    for tok in set(re.findall(r"\b[a-z0-9]+(?:_[a-z0-9]+)+\b|\b[a-z0-9-]+/[a-z0-9._-]+\b", answer)):
        if tok.lower() not in low:
            bad.append(tok)
    return sorted(set(bad))


def main():
    findings = json.loads((OUT / "findings.json").read_text())
    result = {}
    for f in findings:
        if f["risk"] not in ("critical", "high"):
            continue
        facts = tool_results(f)
        v, text = template(f)
        source, note = "template", ""
        try:
            prompt = ("You are a supply-chain security analyst. Using ONLY the tool results below, answer in exactly "
                      "2 sentences. Start with one word: malicious, suspicious or benign, then a colon and why. "
                      "Do not mention any file, line, number or package that is not in the tool results.\n\n"
                      + facts + "\n\nVERDICT:")
            model, ans = ask_model(prompt)
            first = ans.split()[0].strip(":.,").lower() if ans.split() else ""
            bad = ungrounded(ans, facts)
            if first in VERDICTS and not bad:
                v, text, source = first, ans, f"ollama:{model} (grounding check passed)"
            else:
                note = f"model answer rejected: ungrounded={bad} first_word={first!r}"
        except Exception as e:
            note = f"ollama unavailable ({type(e).__name__}); template used"
        result[f["id"]] = {"verdict": v, "verdict_text": text, "source": source, "note": note}
        print(f["id"], f["type"], "->", v, "|", source, note)
    (OUT / "agent.json").write_text(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()
