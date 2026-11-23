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

## Graph legend / blast radius
orange = TurtleBot3 workspace · blue = ROS packages in the image (size = build-time blast radius) · red = suspicious/planted · **amber ring = a runtime ROS package (reached via depend/exec_depend/build_export_depend) whose OWN executables/libraries link DIRECTLY (readelf `NEEDED` entries, not the transitive ldd chain) a library with runtime CVEs.** Ubiquitous base libraries (libc6, libstdc++6, libgcc-s1, libpython3.12*) are ignored for the ring only; their CVEs stay in the CVE list and funnel.
Blast radius = how many of the 12 TurtleBot3 workspace packages depend on a package, **build-time** (all dependency types) and **runtime** (depend/exec_depend/build_export_depend). Build-tool compromise is how the SolarWinds and XZ Utils attacks worked, so build-time hubs matter.

## Fake-malware test (P7-P9, decoy D2) - nothing is ever executed
On the local `planted` branch of `target/`: P7 `rclpy_utils` (typosquat of rclpy; setup.py holds a base64 payload that, decoded, would read `~/.ssh/id_rsa` + `AWS_SECRET_ACCESS_KEY` and POST them to `exfil.example.invalid`), P8 (a line that would download and run a "miner" from `miner.example.invalid`), P9 (the standard EICAR test file, generated at scan time by `guardian/make_eicar.py` into `out/planted_ws`, never committed; the string is assembled from pieces), decoy D2 `robot_status_icons` (base64 PNG icon, must not be flagged). The fixture code is gated behind an env var that is never set and uses only reserved `.invalid` hosts.
Detection: `suspicious.py` decodes base64/hex strings (binary such as PNG is recognised and ignored) and scans the decoded text for credential access, POST exfiltration, download-and-execute and obfuscation, showing the encoded line AND the decoded snippet; ClamAV (official `clamav/clamav` Docker image, signatures shipped in the image) scans the extracted planted workspace, with an EICAR-string fallback if ClamAV is unavailable. The agent has a `decode_payload(file, line)` tool.

## Detection rules (suspicious.py)
unexpected new dependency · typosquat (edit distance <= 2 of a real package, or official prefix `nav2_ ros_ rclpy turtlebot3_` while not in the official list) · install-time code in setup.py (AST: file writes, subprocess, network, eval/exec, cmdclass hooks; never executed) · branch-pinned repos · curl|bash · unpinned base image · unofficial apt source · tag-pinned CI actions.

## CVE prioritisation
Exposure: runtime (reachable via exec/depend/export/apt-Depends edges) vs build/dev-only (`-dev`, headers, compilers, build/test-only paths) vs base image only. Reachability: C/C++ library in the `ldd` closure of binaries of the packages started by the TurtleBot3 launch files (resolved with `dpkg -S` inside the image), or Python modules imported by those nodes. Provenance: Ubuntu / ROS apt repo / PyPI / unknown. Plus severity and fix availability. Top 10 shows at most 3 CVEs per package.

## Recommended actions (all reachable CVEs, 3 tiers)
Every runtime + reachable CVE (42 unique IDs; 6 upgrade + 13 mitigate + 23 monitor) lands in exactly one tier, and each CVE ID is listed once with the number of libraries it affects: **1 Upgrade** (a fixed version exists; grouped by package, target = highest fixed version) · **2 Remove / isolate** (no fix; the library is linked only by the visualisation family rviz2 / rviz_* / nav2_rviz_plugins; if the runtime dependency graph shows robot packages that depend on them, the action is downgraded to **mitigate** and names them) · **3 Escalate / monitor** (no fix; needed by robot runtime packages). Each action lists expected risk reduction, compatibility impact, rollback (keep the previous image tag) and the CVE IDs. **Recommendations only; fixing happens on Day 2 with human approval.**

## What's risky table
Sorted by Guardian priority, not raw Trivy severity: suspicious findings first, then runtime + reachable CVEs, then the rest by score. Columns: priority, exposure (runtime / build/dev-only / base image only), reachable (yes/no), raw Trivy severity. Click a row for verified evidence and the priority reasons. `linux-libc-dev` rows rank low ("build-only kernel headers").

## Results (this run)
- Components: apt 1663, pip 138, ROS 375, source 19, CI 1, image 2. Relations: 12 workspace root, 34 direct, 1708 transitive, 545 base image only (incl. unresolved rosdep keys).
- **CVE funnel (unique CVE IDs): 1,391 -> 1,372 in the robot's tree -> 358 runtime -> 42 reachable** (as CVE x library pairs: 3,444 -> 3,389 -> 1,484 -> 53; one CVE can affect several libraries). The top 10 are libc6 / libassimp5 / libtinyxml2 CVEs linked by Nav2 and rviz2 binaries. `linux-libc-dev` (1,005 CVEs) scores low: "build-only kernel headers".
- Planted risks found **9/9** (P1-P6 supply chain, P7-P9 fake malware), false alarms **0**, both decoys (`robot_battery_monitor`, `robot_status_icons`) not flagged; 15 findings in total (several planted risks raise more than one finding; P7 needs typosquat + obfuscated payload + credential access + exfiltration).
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

## Day 2, Stage A - Gazebo validation (branch `day2`)
```bash
scripts/build_target_image.sh main main        # colcon build inside a gurdy2/ros:jazzy container -> image tb3-target:main
scripts/build_target_image.sh planted planted  # -> tb3-target:planted (nav2_param_utils / rclpy_utils removed from the build context, never executed;
                                               #    their intended effect is applied as a labelled "simulated effect" step on a copy of the Nav2 params)
scripts/mission_test.py --image tb3-target:main --label main_1      # PASS/FAIL, out/mission_main_1.json   (GUI=true for the WSLg window)
```
Mission: TurtleBot3 world (offline copy, `scripts/mission/mission_world.sdf`) + ONE 0.4 m box at (-0.55, -0.5) on the straight line start (-2, -0.5) -> goal (1.6, -0.5), not in the static map. One NavigateToPose goal, 120 s wall-clock limit, `--network none` container removed afterwards. Never run together with the gurdy2 stack (the script refuses).
Results (4 runs, saved in `results/day2_stageA/`): see the dashboard "Validation" tab. Distances use Gazebo ground truth; the contact sensor and distance were validated with a positive control (`scripts/mission/positive_control.sh`). An earlier odometry-based distance gave a false collision and was dropped.
