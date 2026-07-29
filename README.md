# AI LAD

AI LAD is a desktop log anomaly detection and forensic analysis tool built with Python and CustomTkinter.

It combines:
- live log monitoring
- anomaly detection
- automated response rules
- alert and report generation
- optional LLM-assisted forensic analysis

## Features

- Live Monitor for streaming logs and threat summaries
- Dashboard with current system and security metrics
- Alerts and Anomalies view
- Response Rules management
- Reports export
- LLM Forensics page for log analysis
- Evaluation and benchmark scripts for detector testing

## Screenshots

These are the actual UI screenshots included with the project.

<table>
  <tr>
    <td><img src="assets/ss/DashBoard%20UI.png" alt="Dashboard screenshot" width="100%"></td>
    <td><img src="assets/ss/Live%20Monitor%20Page.png" alt="Live Monitor screenshot" width="100%"></td>
  </tr>
  <tr>
    <td><img src="assets/ss/Alerts%20and%20Anomalies.png" alt="Alerts screenshot" width="100%"></td>
    <td><img src="assets/ss/Reports%20Page.png" alt="Reports screenshot" width="100%"></td>
  </tr>
  <tr>
    <td><img src="assets/ss/AI%20Forensic%20page.png" alt="AI Forensic screenshot" width="100%"></td>
    <td><img src="assets/ss/Log%20Analysis%20using%20LLM.png" alt="LLM analysis screenshot" width="100%"></td>
  </tr>
</table>

## Project Structure

- `AiLogGuard.py` - main launcher
- `src/controller/main.py` - app controller and page navigation
- `src/backend/` - database, detection, evaluation, and LLM services
- `src/ui/pages/` - all desktop UI pages
- `assets/` - icons, prompt template, and ML model files
- `data/` - runtime storage for local logs and databases
- `reports/` - generated evaluation and benchmark outputs
- `assets/ss/` - README screenshots

## Requirements

Use Python 3.11+ if possible.

Main dependencies are listed in `requirements.txt`, including:
- `customtkinter`
- `matplotlib`
- `requests`
- `pydantic`
- `openai`
- `scikit-learn`
- `psutil`
- `reportlab`

Optional:
- `cartopy` for the threat intel map

## Setup

Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you use a different environment name, adjust the activation command accordingly.

## Configuration

The app reads the OpenRouter API key from an environment variable.

Preferred:

```bash
export OPENROUTER_API_KEY="your_key_here"
```

Fallback:

```bash
export LLM_API_KEY="your_key_here"
```

## Run the App

From the project root:

```bash
python AiLogGuard.py
```

If you are using the project virtual environment directly:

```bash
./.venv/bin/python AiLogGuard.py
```

## Evaluation

Run a quick sample evaluation with your own dataset:

```bash
python evaluate_detector.py --input data/logs/evaluation_sample.csv --require-ml
```

Run on a labeled dataset:

```bash
python evaluate_detector.py \
  --input "path/to/your_dataset.csv" \
  --log-column Content \
  --label-column AnomalyLabel \
  --require-ml
```

## Benchmarking

Run detector benchmarks:

```bash
python benchmark_detector.py \
  --inputs \
  "path/to/dataset_1.csv" \
  "path/to/dataset_2.csv" \
  --log-column Content \
  --runs 5 \
  --warmup-runs 1 \
  --require-ml
```

## Visualizations

Create evaluation charts:

```bash
MPLCONFIGDIR=/tmp/mplcfg python visualize_evaluation.py \
  --inputs "reports/detector_evaluation_*.json" \
  --outdir reports/visualizations
```

Create benchmark charts:

```bash
MPLCONFIGDIR=/tmp/mplcfg python visualize_benchmark.py \
  --inputs "reports/detector_benchmark_*.json" \
  --outdir reports/visualizations
```

## Full Pipeline

The repository includes a shell script for the full evaluation and benchmark flow:

```bash
./run_full_pipeline.sh
```

## Notes

- Generated outputs are ignored by Git, including `reports/`, `data/logs/`, and local database files.
- The repository does not bundle training/evaluation datasets. Bring your own CSV files for evaluation and benchmarking.
- The app can fall back to placeholder pages if optional dependencies are missing.
- If the threat intel map is unavailable, install `cartopy` to enable the full map view.
