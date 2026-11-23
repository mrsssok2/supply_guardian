# Software Supply Chain Guardian (hackathon Day 1 checkpoint)

Detection-only dashboard for a ROS 2 (Jazzy) TurtleBot3 robot: **what is inside**, **what changed**, **what is risky** — with evidence.
Public open-source code only, everything local, nothing published, no real secrets.

## Run
```bash
./run.sh   # discover -> prioritise CVEs -> detect changes -> AI investigator -> Streamlit on http://127.0.0.1:8501
```
Needs Docker + local image `gurdy2/ros:jazzy`, Trivy (`~/.local/bin/trivy`), a Python venv (`.venv`, created by run.sh).
AI verdicts need a local Ollama on `127.0.0.1:11435` (e.g. `OLLAMA_HOST=127.0.0.1:11435 OLLAMA_MODELS=~/ollama_models ~/ollama/bin/ollama serve`); without it the agent uses a rule-based template.

## Layout
- `target/` – its own git repo (not tracked here): TurtleBot3 workspace (`robot_ws/src`, commits pinned in `robot.repos`), `Dockerfile`, CI workflow. Branch `main` = clean, local branch `planted` = 6 harmless planted risks + 1 decoy.
- `guardian/discover.py` – Trivy SBOM + CVEs, every `package.xml` (workspace + image `/opt/ros/jazzy/share`) -> networkx graph; each component gets layer, relation and shortest path from the TurtleBot3 packages.
- `guardian/prioritize.py` – CVE priority score and funnel (exposure x reachability x provenance x severity x fix).
- `guardian/suspicious.py` – diff `main..planted` -> findings, scored against `GROUND_TRUTH.json`.
- `guardian/agent.py` – investigator agent (local Ollama, tools read_file / git_diff / dependency_path / scan_setup_py, max 5 calls) with grounding check + template fallback.
- `dashboard/app.py` – Streamlit: What's inside / What changed / What's risky; "Verified evidence" (tool/file facts) is separate from "AI inference".

## Relations
*workspace root* = a TurtleBot3 package itself · *direct* / *transitive* = reached from a TurtleBot3 package by one / several dependency hops · *base image only* = present in the image, but no TurtleBot3 dependency path leads to it.

## Detection rules (suspicious.py)
unexpected new dependency · typosquat (edit distance <= 2 of a real package, or official prefix `nav2_ ros_ rclpy turtlebot3_` while not in the official list) · install-time code in setup.py (AST: file writes, subprocess, network, eval/exec, cmdclass hooks; never executed) · branch-pinned repos · curl|bash · unpinned base image · unofficial apt source · tag-pinned CI actions.

## CVE prioritisation
Exposure: runtime (reachable via exec/depend/export/apt-Depends edges) vs build/dev-only (`-dev`, headers, compilers, build/test-only paths) vs base image only. Reachability: C/C++ library in the `ldd` closure of binaries of the packages started by the TurtleBot3 launch files (resolved with `dpkg -S` inside the image), or Python modules imported by those nodes. Provenance: Ubuntu / ROS apt repo / PyPI / unknown. Plus severity and fix availability. Top 10 shows at most 3 CVEs per package.

## Results (this run)
- Components: apt 1663, pip 138, ROS 375, source 19, CI 1, image 2. Relations: 12 workspace root, 34 direct, 1708 transitive, 545 base image only (incl. unresolved rosdep keys).
- **CVE funnel: 3,444 CVEs -> 3,389 in the robot's tree -> 1,484 runtime -> 53 reachable -> top 10.** The top 10 are libc6 / libassimp5 / libtinyxml2 CVEs linked by Nav2 and rviz2 binaries. `linux-libc-dev` (1,005 CVEs) scores low: "build-only kernel headers".
- Planted risks found **6/6**, false alarms **0**, decoy `robot_battery_monitor` not flagged (8 findings: P1 and P2 also raise a typosquat finding; P4 needs unpinned-base + curl|bash).
- AI investigator (qwen3:1.7b via Ollama): 7 critical/high findings, 7 grounded model verdicts, 0 template fallbacks in the final run. In an earlier run one answer mentioned a file no tool had returned and was rejected -> template, so the check does trigger. The verdict is nondeterministic between runs despite temperature 0.

## Limitations
- The runtime image is the local `gurdy2/ros:jazzy` (ROS 2 Jazzy + Nav2 + slam_toolbox + ros_gz), **not built from `target/Dockerfile`**; the Dockerfile only documents the intended build. The TurtleBot3 packages themselves are not installed in that image, so reachability covers the Nav2/rviz2/Gazebo/cartographer nodes the launch files start, not turtlebot3_node.
- 101 rosdep keys in package.xml files (76 before `test_depend` was parsed) do not resolve to an installed apt package; they are excluded from layer counts.
- Everything is heuristic: name/prefix rules, regex-based launch-file parsing (Python launch files only), dependency edges from dpkg `Depends`, pattern list for build-only packages, and the priority weights are hand-picked, not calibrated. Reachability only proves a library is loaded, not that the vulnerable function is called.
- Trivy found no language-specific CVEs (ROS python packages are installed via apt); the pip layer comes from SBOM pypi entries.
- The small local model over-calls severity (it labelled hygiene findings "malicious" before a cap was added: unpinned/branch/tag pins are capped at "suspicious"). Treat AI inference as a second opinion, never as evidence.
- Detection thresholds were tuned on this single planted scenario.

## Tools
Trivy 0.76.2, Docker, git, Python (networkx, pandas, pyvis, Streamlit, PyYAML), Ollama (qwen3:1.7b).
