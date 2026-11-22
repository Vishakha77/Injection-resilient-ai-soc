#!/usr/bin/env bash
# One-command setup + first run for Ubuntu 22.04 / 24.04.
#   bash setup_ubuntu.sh            -> install everything, run offline test
#   bash setup_ubuntu.sh --ollama   -> also install Ollama + llama3.1:8b and run with the real LLM
set -euo pipefail
cd "$(dirname "$0")"

echo "==> [1/4] System packages (asks for your sudo password)"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq suricata python3-pip python3-venv jq tcpreplay
suricata -V

echo "==> [2/4] Python environment"
[ -d .venv ] || python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt
chmod +x scripts/run_all.sh

echo "==> [3/4] Offline test run (simulated LLM)"
./scripts/run_all.sh

if [ "${1:-}" = "--ollama" ]; then
  echo "==> [4/4] Ollama + llama3.1:8b (about 5 GB download)"
  command -v ollama >/dev/null || curl -fsSL https://ollama.com/install.sh | sh
  if ! curl -s localhost:11434 >/dev/null; then (ollama serve >/tmp/ollama.log 2>&1 &); sleep 3; fi
  ollama pull llama3.1:8b
  ./scripts/run_all.sh --backend ollama --model llama3.1:8b --sample 10
else
  echo "==> [4/4] Skipped real LLM. Run again with --ollama when ready."
fi

echo
echo "Done. Start the dashboard with:"
echo "  cd $(pwd) && source .venv/bin/activate && streamlit run app/dashboard.py"
