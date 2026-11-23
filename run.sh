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
# serve out/ (graph_full.html) on 127.0.0.1:8502 for the dashboard link; both servers are stopped when run.sh stops
python3 -m http.server 8502 --bind 127.0.0.1 --directory out > /dev/null 2>&1 &
HTTP_PID=$!
$PY -m streamlit run dashboard/app.py --server.headless true --server.address 127.0.0.1 --server.port 8501 &
ST_PID=$!
trap 'kill $HTTP_PID $ST_PID 2>/dev/null' EXIT INT TERM
wait $ST_PID
