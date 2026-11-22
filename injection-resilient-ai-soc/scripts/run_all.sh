#!/usr/bin/env bash
# Usage:
#   ./scripts/run_all.sh                                  # offline, simulated LLM
#   ./scripts/run_all.sh --backend ollama --model llama3.1:8b --sample 40
#   ./scripts/run_all.sh --backend openai --model gpt-4o-mini --sample 40   (needs OPENAI_API_KEY)
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src
python3 -m aisoc.cli all "$@"
echo
echo "Dashboard:  streamlit run app/dashboard.py"
