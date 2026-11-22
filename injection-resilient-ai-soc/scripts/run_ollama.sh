#!/usr/bin/env bash
# Step 4: real-LLM run with safe result copies.  Usage: ./scripts/run_ollama.sh [model] [sample]
set -euo pipefail
cd "$(dirname "$0")/.."
MODEL="${1:-llama3.1:8b}"; SAMPLE="${2:-10}"
TAG="ollama_$(echo "$MODEL" | tr ':/' '__')"     # llama3.1:8b -> ollama_llama3.1_8b
command -v ollama >/dev/null || { echo "Ollama not installed: curl -fsSL https://ollama.com/install.sh | sh"; exit 1; }
curl -s localhost:11434 >/dev/null || { echo "Starting ollama serve..."; (ollama serve >/tmp/ollama.log 2>&1 &); sleep 3; }
ollama list | grep -q "^$MODEL" || ollama pull "$MODEL"
if [ ! -f results/runs/simulated/metrics.csv ]; then
  mkdir -p results/runs/simulated && cp results/metrics.csv results/meta.json results/examples.txt results/runs/simulated/ 2>/dev/null || true
fi
./scripts/run_all.sh --backend ollama --model "$MODEL" --sample "$SAMPLE" 2>&1 | tee "/tmp/aisoc_${TAG}.log"
if grep -q "LLM calls FAILED" "/tmp/aisoc_${TAG}.log"; then
  echo; echo "!!! Some LLM calls failed - results NOT copied. See WARNING lines above."; exit 2
fi
mkdir -p "results/runs/$TAG" && cp results/metrics.csv results/meta.json results/examples.txt "/tmp/aisoc_${TAG}.log" "results/runs/$TAG/" 2>/dev/null || true
echo; python3 scripts/compare_runs.py results/runs/simulated "results/runs/$TAG"
