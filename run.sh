#!/usr/bin/env bash
# discover -> prioritise CVEs -> detect -> AI investigator (Ollama on :11435, else template) -> dashboard. Everything local.
set -euo pipefail
cd "$(dirname "$0")"
PY=.venv/bin/python
[ -x "$PY" ] || { python3 -m venv .venv && .venv/bin/python -m pip install -q streamlit networkx pyvis pandas pyyaml; }
export PATH="$HOME/.local/bin:$PATH"
$PY guardian/discover.py
$PY guardian/prioritize.py
$PY guardian/suspicious.py main planted
[ -f guardian/agent.py ] && $PY guardian/agent.py || true
$PY guardian/graph_full.py
exec $PY -m streamlit run dashboard/app.py --server.headless true --server.address 127.0.0.1 --server.port 8501
