# AI-Log-Guard Execution Guide

This guide shows exactly how to run:
- evaluation
- benchmarking
- visualization

All commands assume your terminal is in:
`AI-Log-Guard/FYP Project`

---

## 1) Open project and activate environment

```bash
cd "/Users/dhanush/Documents/VS/sample/AI-Log-Guard/FYP Project"
source venv/bin/activate
```

If `venv` is not available:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 2) Run detector evaluation (metrics: accuracy, precision, recall, f1)

### Quick sample check
```bash
python3 evaluate_detector.py --input data/logs/evaluation_sample.csv --require-ml
```

### Run on one labeled dataset
```bash
python3 evaluate_detector.py \
  --input "data/dataset/labeled_data/normalized/HPC_2k_enhanced.csv" \
  --log-column Content \
  --label-column AnomalyLabel \
  --require-ml
```

### Run on multiple datasets (one-by-one loop)
```bash
for f in data/dataset/labeled_data/normalized/*_2k_enhanced.csv; do
  echo "Evaluating $f"
  python3 evaluate_detector.py --input "$f" --log-column Content --label-column AnomalyLabel --require-ml
done
```

Output is saved to:
`reports/detector_evaluation_YYYYMMDD_HHMMSS.json`

---

## 3) Visualize evaluation outputs

```bash
MPLCONFIGDIR=/tmp/mplcfg python3 visualize_evaluation.py \
  --inputs "reports/detector_evaluation_*.json" \
  --outdir reports/visualizations
```

Typical output files:
- `reports/visualizations/metrics_comparison.png`
- `reports/visualizations/<dataset>_binary_confusion.png`
- `reports/visualizations/<dataset>_severity_confusion.png`

---

## 4) Run performance benchmark (throughput + latency)

```bash
python3 benchmark_detector.py \
  --inputs \
  "data/dataset/labeled_data/normalized/HPC_2k_enhanced.csv" \
  "data/dataset/labeled_data/normalized/Windows_2k_enhanced.csv" \
  "data/dataset/labeled_data/normalized/Apache_2k_enhanced.csv" \
  "data/dataset/labeled_data/normalized/Linux_2k_enhanced.csv" \
  "data/dataset/labeled_data/normalized/Zookeeper_2k_enhanced.csv" \
  --log-column Content \
  --runs 5 \
  --warmup-runs 1 \
  --require-ml
```

Output is saved to:
`reports/detector_benchmark_YYYYMMDD_HHMMSS.json`

---

## 5) Visualize benchmark outputs

```bash
MPLCONFIGDIR=/tmp/mplcfg python3 visualize_benchmark.py \
  --inputs "reports/detector_benchmark_*.json" \
  --outdir reports/visualizations
```

Typical output files:
- `reports/visualizations/benchmark_throughput_by_dataset.png`
- `reports/visualizations/benchmark_latency_by_dataset.png`
- `reports/visualizations/benchmark_ai_flag_rate.png`

---

## 6) Full pipeline (copy-paste block)

```bash
cd "/Users/dhanush/Documents/VS/sample/AI-Log-Guard/FYP Project"
source venv/bin/activate

./run_full_pipeline.sh
```

### Recommended one-command runner
`run_full_pipeline.sh` now does:
- hybrid evaluation on all datasets
- ablation evaluation (`heuristic_only` + `ml_only`)
- benchmark
- visualizations from current run outputs only (no old-report duplicates)

Optional controls:
```bash
RUN_ABLATION=1 RUNS=5 WARMUP_RUNS=1 BOOTSTRAP_SAMPLES=400 CI_CONF_LEVEL=0.95 BENCHMARK_MODE=hybrid MAX_ROWS=500 ./run_full_pipeline.sh
```

---

## 7) Common issues and fixes

1. `cd: no such file or directory: AI-Log-Guard/FYP Project`
- You are already inside that folder.
- Check with:
```bash
pwd
```

2. `[Errno 2] No such file or directory: 'your.csv'`
- Replace `your.csv` with a real existing path.
- Check file:
```bash
ls -l data/logs/evaluation_sample.csv
```

3. Matplotlib cache warning
- Use:
```bash
MPLCONFIGDIR=/tmp/mplcfg
```
