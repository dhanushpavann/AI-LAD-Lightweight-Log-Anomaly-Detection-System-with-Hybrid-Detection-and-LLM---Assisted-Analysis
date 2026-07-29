#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="$ROOT_DIR/venv/bin/python"
MPL_CFG_DIR="${MPLCONFIGDIR:-/tmp/mplcfg}"
RUNS="${RUNS:-5}"
WARMUP_RUNS="${WARMUP_RUNS:-1}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
RUN_ABLATION="${RUN_ABLATION:-1}"
BOOTSTRAP_SAMPLES="${BOOTSTRAP_SAMPLES:-400}"
CI_CONF_LEVEL="${CI_CONF_LEVEL:-0.95}"
CI_SEED="${CI_SEED:-42}"
BENCHMARK_MODE="${BENCHMARK_MODE:-hybrid}"
MAX_ROWS="${MAX_ROWS:-}"

DATASETS=(
  "$ROOT_DIR/data/dataset/labeled_data/normalized/HPC_2k_enhanced.csv"
  "$ROOT_DIR/data/dataset/labeled_data/normalized/Windows_2k_enhanced.csv"
  "$ROOT_DIR/data/dataset/labeled_data/normalized/Apache_2k_enhanced.csv"
  "$ROOT_DIR/data/dataset/labeled_data/normalized/Linux_2k_enhanced.csv"
  "$ROOT_DIR/data/dataset/labeled_data/normalized/Zookeeper_2k_enhanced.csv"
)

section() {
  printf "\n============================================================\n"
  printf "%s\n" "$1"
  printf "============================================================\n"
}

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "[ERROR] Python not found at: $PYTHON_BIN"
  echo "Activate/create venv first."
  exit 1
fi

for dataset in "${DATASETS[@]}"; do
  if [[ ! -f "$dataset" ]]; then
    echo "[ERROR] Missing dataset: $dataset"
    exit 1
  fi
done

HYBRID_EVAL_REPORTS=()
ABLATION_EVAL_REPORTS=()
ALL_EVAL_REPORTS=()

section "1) EVALUATION (ALL DATASETS)"
for dataset in "${DATASETS[@]}"; do
  dataset_name="$(basename "$dataset" .csv)"
  output_path="$ROOT_DIR/reports/detector_evaluation_${RUN_ID}_${dataset_name}_hybrid.json"
  echo "[RUN] Evaluating ${dataset_name} (hybrid)"
  cmd=(
    "$PYTHON_BIN" "$ROOT_DIR/evaluate_detector.py"
    --input "$dataset"
    --log-column Content
    --label-column AnomalyLabel
    --require-ml
    --detection-mode hybrid
    --bootstrap-samples "$BOOTSTRAP_SAMPLES"
    --ci-confidence-level "$CI_CONF_LEVEL"
    --ci-seed "$CI_SEED"
  )
  if [[ -n "$MAX_ROWS" ]]; then
    cmd+=(--max-rows "$MAX_ROWS")
  fi
  cmd+=(--output "$output_path")
  "${cmd[@]}"
  HYBRID_EVAL_REPORTS+=("$output_path")
  ALL_EVAL_REPORTS+=("$output_path")
done

if [[ "$RUN_ABLATION" == "1" ]]; then
  section "1B) EVALUATION ABLATION (HEURISTIC_ONLY + ML_ONLY)"
  for mode in heuristic_only ml_only; do
    for dataset in "${DATASETS[@]}"; do
      dataset_name="$(basename "$dataset" .csv)"
      output_path="$ROOT_DIR/reports/detector_evaluation_${RUN_ID}_${dataset_name}_${mode}.json"
      echo "[RUN] Evaluating ${dataset_name} (${mode})"
      cmd=(
        "$PYTHON_BIN" "$ROOT_DIR/evaluate_detector.py"
        --input "$dataset"
        --log-column Content
        --label-column AnomalyLabel
        --detection-mode "$mode"
        --bootstrap-samples "$BOOTSTRAP_SAMPLES"
        --ci-confidence-level "$CI_CONF_LEVEL"
        --ci-seed "$CI_SEED"
      )
      if [[ "$mode" == "ml_only" ]]; then
        cmd+=(--require-ml)
      fi
      if [[ -n "$MAX_ROWS" ]]; then
        cmd+=(--max-rows "$MAX_ROWS")
      fi
      cmd+=(--output "$output_path")
      "${cmd[@]}"
      ABLATION_EVAL_REPORTS+=("$output_path")
      ALL_EVAL_REPORTS+=("$output_path")
    done
  done
fi

section "2) BENCHMARK (ALL DATASETS)"
BENCHMARK_OUTPUT="$ROOT_DIR/reports/detector_benchmark_${RUN_ID}_${BENCHMARK_MODE}.json"
cmd=(
  "$PYTHON_BIN" "$ROOT_DIR/benchmark_detector.py"
  --inputs "${DATASETS[@]}"
  --log-column Content
  --runs "$RUNS"
  --warmup-runs "$WARMUP_RUNS"
  --require-ml
  --detection-mode "$BENCHMARK_MODE"
)
if [[ -n "$MAX_ROWS" ]]; then
  cmd+=(--max-rows "$MAX_ROWS")
fi
cmd+=(--output "$BENCHMARK_OUTPUT")
"${cmd[@]}"

section "3) VISUALIZE EVALUATION"
MPLCONFIGDIR="$MPL_CFG_DIR" "$PYTHON_BIN" "$ROOT_DIR/visualize_evaluation.py" \
  --inputs "${ALL_EVAL_REPORTS[@]}" \
  --outdir "$ROOT_DIR/reports/visualizations" \
  --prefix "${RUN_ID}_"

section "4) VISUALIZE BENCHMARK"
MPLCONFIGDIR="$MPL_CFG_DIR" "$PYTHON_BIN" "$ROOT_DIR/visualize_benchmark.py" \
  --inputs "$BENCHMARK_OUTPUT" \
  --outdir "$ROOT_DIR/reports/visualizations" \
  --prefix "${RUN_ID}_"

section "DONE"
echo "Run ID: $RUN_ID"
echo "Outputs:"
for f in "${ALL_EVAL_REPORTS[@]}"; do
  echo "- Evaluation JSON: $f"
done
echo "- Benchmark JSON:  $BENCHMARK_OUTPUT"
echo "- Visualizations:  $ROOT_DIR/reports/visualizations/${RUN_ID}_*.png"
