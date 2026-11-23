# Software Supply Chain Guardian (hackathon Day 1 checkpoint)

Detection-only dashboard for a ROS 2 (Jazzy) TurtleBot3 robot: **what is inside**, **what changed**, **what is risky** — with evidence.
Everything runs locally on public open-source code; nothing is published; no real secrets.

## Run
```bash
./run.sh          # discover -> detect -> AI verdicts -> Streamlit on http://127.0.0.1:8501
```
Needs: Docker, local image `gurdy2/ros:jazzy`, Trivy (`~/.local/bin/trivy`), Python venv (`.venv`, created by run.sh). Optional: Ollama on port 11435 for AI verdicts.

## Layout
- `target/` – its own git repo: TurtleBot3 workspace (`robot_ws/src`, commits pinned in `robot.repos`), `Dockerfile`, CI workflow. Branch `main` = clean; local branch `planted` = 6 harmless planted risks + 1 decoy. (Not tracked by this repo; recreate by cloning per `robot.repos`.)
- `guardian/discover.py` – Trivy SBOM+CVEs on the image, every `package.xml` (workspace + image `/opt/ros/jazzy/share`) -> networkx graph; components with layer/direct-transitive/shortest path from turtlebot3; CVEs with path to a ROS package. -> `out/components.json graph.json cves.json`
- `guardian/suspicious.py` – diff `main..planted`; rules: unexpected dependency, typosquat-like name, install-time code in setup.py (AST, never executed), branch-pinned repos, curl|bash, unpinned base image, unofficial apt source, tag-pinned CI actions. -> `out/findings.json`, scored vs `GROUND_TRUTH.json`.
- `guardian/agent.py` – grounded verdicts for critical/high findings via local Ollama; answers mentioning any file/number/package not in the tool results are rejected -> template fallback.
- `dashboard/app.py` – Streamlit: What's inside / What changed / What's risky (verified evidence vs separate AI inference box).

## Results (this run)
- Image `gurdy2/ros:jazzy`: 1663 apt, 138 pip, 375 ROS, 19 source, 1 CI, 2 image components; 2274 graph nodes.
- Trivy: 3444 CVEs (8 critical, 221 high, 2445 medium, 770 low); 3387 have a path back to a ROS package.
- Planted risks found: **6/6**, false alarms: **0**, decoy (`robot_battery_monitor`) not flagged. 8 findings in total (P1 and P2 each also trigger a typosquat finding; P4 needs both unpinned-base and curl|bash).

## Tools
Trivy 0.76.2, Docker, Python (networkx, pandas, pyvis, Streamlit, PyYAML), git, optional Ollama.

## Limits (honest notes)
- Ollama was not running during the build, so verdicts in `out/agent.json` come from the **template fallback**; the Ollama path and grounding check were only unit-tested with canned answers.
- Trivy found no language-specific CVEs (ROS python packages are installed via apt); pip layer = SBOM pypi entries.
- 76 rosdep keys in package.xml files did not resolve to an installed apt package; they are excluded from layer counts.
- Detection thresholds are tuned to this demo; the typosquat rule needs >=10 real packages sharing the namespace prefix.
