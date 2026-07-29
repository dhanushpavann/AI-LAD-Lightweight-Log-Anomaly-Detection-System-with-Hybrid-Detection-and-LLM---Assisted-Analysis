#!/usr/bin/env python3
import argparse
import csv
import json
import math
import os
import statistics
import sys
import time
from datetime import datetime
from glob import glob
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.backend.evaluation import build_evaluation_corelogic
from src.backend.core_logic import SKLEARN_AVAILABLE


DEFAULT_LOG_COLUMNS = ["log_line", "line", "message", "log", "raw_log", "text", "Content"]


def _resolve_input_paths(inputs: List[str]) -> List[str]:
    matched: List[str] = []
    for item in inputs:
        if os.path.isfile(item):
            matched.append(os.path.abspath(item))
            continue
        hits = sorted(glob(item))
        for h in hits:
            if os.path.isfile(h):
                matched.append(os.path.abspath(h))

    deduped: List[str] = []
    seen = set()
    for path in matched:
        if path not in seen:
            deduped.append(path)
            seen.add(path)
    return deduped


def _resolve_log_column(headers: List[str], explicit: Optional[str]) -> str:
    normalized = {h.strip().lower(): h for h in headers}
    if explicit:
        key = explicit.strip().lower()
        if key in normalized:
            return normalized[key]
        raise ValueError(f"Requested log column '{explicit}' not found in headers: {headers}")

    for candidate in DEFAULT_LOG_COLUMNS:
        key = candidate.strip().lower()
        if key in normalized:
            return normalized[key]
    raise ValueError(
        "Could not auto-detect log column. "
        f"Tried {DEFAULT_LOG_COLUMNS}, available headers: {headers}"
    )


def _load_log_lines(csv_path: str, log_column: Optional[str], max_rows: Optional[int]) -> Tuple[str, int, List[str]]:
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if not rows:
        raise ValueError(f"No rows in dataset: {csv_path}")

    headers = reader.fieldnames or list(rows[0].keys())
    resolved_log_col = _resolve_log_column(headers, log_column)

    lines: List[str] = []
    for row in rows:
        value = (row.get(resolved_log_col) or "").strip()
        if value:
            lines.append(value)
        if max_rows is not None and len(lines) >= max_rows:
            break

    return resolved_log_col, len(rows), lines


def _percentile(sorted_values: List[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (len(sorted_values) - 1) * p
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return sorted_values[lo]
    weight = rank - lo
    return sorted_values[lo] * (1.0 - weight) + sorted_values[hi] * weight


def _latency_summary(latencies_ms: List[float]) -> Dict[str, float]:
    if not latencies_ms:
        return {
            "min": 0.0,
            "max": 0.0,
            "mean": 0.0,
            "std": 0.0,
            "p50": 0.0,
            "p95": 0.0,
            "p99": 0.0,
        }
    sorted_vals = sorted(latencies_ms)
    return {
        "min": float(sorted_vals[0]),
        "max": float(sorted_vals[-1]),
        "mean": float(statistics.fmean(sorted_vals)),
        "std": float(statistics.pstdev(sorted_vals)) if len(sorted_vals) > 1 else 0.0,
        "p50": float(_percentile(sorted_vals, 0.50)),
        "p95": float(_percentile(sorted_vals, 0.95)),
        "p99": float(_percentile(sorted_vals, 0.99)),
    }


def _benchmark_single_dataset(
    detector,
    csv_path: str,
    *,
    log_column: Optional[str],
    max_rows: Optional[int],
    warmup_runs: int,
    runs: int,
    detection_mode: str = "hybrid",
) -> Dict[str, Any]:
    resolved_log_col, rows_total, lines = _load_log_lines(csv_path, log_column, max_rows)
    if not lines:
        raise ValueError(f"No non-empty log lines found in dataset: {csv_path}")

    # Warmup (excluded from results)
    for _ in range(max(0, warmup_runs)):
        for line in lines:
            detector.detect_line_for_evaluation(line, detection_mode=detection_mode)

    run_stats: List[Dict[str, Any]] = []
    all_latencies: List[float] = []
    total_processed = 0
    total_ai_flags = 0
    throughput_values: List[float] = []

    for run_idx in range(1, max(1, runs) + 1):
        run_latencies: List[float] = []
        ai_flag_count = 0

        t_start = time.perf_counter()
        for line in lines:
            t0 = time.perf_counter_ns()
            result = detector.detect_line_for_evaluation(line, detection_mode=detection_mode)
            t1 = time.perf_counter_ns()
            if result is None:
                continue
            run_latencies.append((t1 - t0) / 1_000_000.0)  # ms
            if bool(result.get("ai_flag")):
                ai_flag_count += 1
        t_end = time.perf_counter()

        processed = len(run_latencies)
        duration_sec = max(t_end - t_start, 1e-12)
        throughput = processed / duration_sec
        throughput_values.append(throughput)

        run_summary = {
            "run_index": run_idx,
            "processed_rows": processed,
            "duration_sec": duration_sec,
            "throughput_logs_per_sec": throughput,
            "ai_flag_count": ai_flag_count,
            "latency_ms": _latency_summary(run_latencies),
        }
        run_stats.append(run_summary)

        total_processed += processed
        total_ai_flags += ai_flag_count
        all_latencies.extend(run_latencies)

    dataset_name = Path(csv_path).stem
    agg_latency = _latency_summary(all_latencies)
    agg = {
        "runs": len(run_stats),
        "total_processed_rows_across_runs": total_processed,
        "throughput_logs_per_sec_mean": float(statistics.fmean(throughput_values)) if throughput_values else 0.0,
        "throughput_logs_per_sec_std": float(statistics.pstdev(throughput_values)) if len(throughput_values) > 1 else 0.0,
        "ai_flag_rate": (total_ai_flags / total_processed) if total_processed else 0.0,
        "latency_ms": agg_latency,
    }

    return {
        "dataset_name": dataset_name,
        "input_csv_path": os.path.abspath(csv_path),
        "resolved_log_column": resolved_log_col,
        "rows_total_in_csv": rows_total,
        "rows_benchmarked_per_run": len(lines),
        "warmup_runs": max(0, warmup_runs),
        "detection_mode": detection_mode,
        "run_stats": run_stats,
        "aggregate": agg,
    }


def _overall_summary(dataset_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not dataset_reports:
        return {
            "datasets_benchmarked": 0,
            "total_rows_processed_across_runs": 0,
            "overall_throughput_logs_per_sec_weighted_mean": 0.0,
            "overall_latency_ms_weighted_mean": 0.0,
        }

    total_rows = 0
    throughput_weighted_sum = 0.0
    latency_weighted_sum = 0.0

    for ds in dataset_reports:
        agg = ds.get("aggregate", {})
        rows = int(agg.get("total_processed_rows_across_runs", 0))
        total_rows += rows
        throughput_weighted_sum += float(agg.get("throughput_logs_per_sec_mean", 0.0)) * rows
        latency_weighted_sum += float((agg.get("latency_ms") or {}).get("mean", 0.0)) * rows

    return {
        "datasets_benchmarked": len(dataset_reports),
        "total_rows_processed_across_runs": total_rows,
        "overall_throughput_logs_per_sec_weighted_mean": (throughput_weighted_sum / total_rows) if total_rows else 0.0,
        "overall_latency_ms_weighted_mean": (latency_weighted_sum / total_rows) if total_rows else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark AI-Log-Guard detector performance (latency + throughput) across datasets."
    )
    parser.add_argument("--inputs", nargs="+", required=True, help="CSV paths or glob patterns.")
    parser.add_argument("--output", default=None, help="Optional benchmark JSON output path.")
    parser.add_argument("--log-column", default=None, help="Override log column name.")
    parser.add_argument("--max-rows", type=int, default=None, help="Optional max rows per dataset.")
    parser.add_argument("--warmup-runs", type=int, default=1, help="Warmup runs per dataset (excluded).")
    parser.add_argument("--runs", type=int, default=5, help="Measured runs per dataset.")
    parser.add_argument("--require-ml", action="store_true", help="Fail if ML model/vectorizer is not loaded.")
    parser.add_argument(
        "--detection-mode",
        default="hybrid",
        choices=["hybrid", "heuristic_only", "ml_only"],
        help="Detection mode for benchmark ablation.",
    )
    args = parser.parse_args()

    dataset_paths = _resolve_input_paths(args.inputs)
    if not dataset_paths:
        print("[ERROR] No dataset files matched the provided --inputs.", file=sys.stderr)
        return 1

    try:
        detector = build_evaluation_corelogic(require_ml=args.require_ml)
    except Exception as exc:
        print(f"[ERROR] Could not initialize detector for benchmarking: {exc}", file=sys.stderr)
        return 1

    ml_status = {
        "require_ml": args.require_ml,
        "sklearn_available": bool(SKLEARN_AVAILABLE),
        "model_loaded": detector.model is not None,
        "vectorizer_loaded": detector.vectorizer is not None,
    }
    ml_status["ml_ready"] = bool(
        ml_status["sklearn_available"] and ml_status["model_loaded"] and ml_status["vectorizer_loaded"]
    )

    dataset_reports: List[Dict[str, Any]] = []
    failures: List[Dict[str, str]] = []

    for dataset_path in dataset_paths:
        try:
            report = _benchmark_single_dataset(
                detector,
                dataset_path,
                log_column=args.log_column,
                max_rows=args.max_rows,
                warmup_runs=args.warmup_runs,
                runs=args.runs,
                detection_mode=args.detection_mode,
            )
            dataset_reports.append(report)
            agg = report["aggregate"]
            print(
                f"[OK] {report['dataset_name']}: "
                f"throughput_mean={agg['throughput_logs_per_sec_mean']:.2f} logs/s, "
                f"latency_mean={agg['latency_ms']['mean']:.4f} ms, "
                f"p95={agg['latency_ms']['p95']:.4f} ms"
            )
        except Exception as exc:
            failures.append({"dataset": dataset_path, "error": str(exc)})
            print(f"[FAIL] {dataset_path}: {exc}", file=sys.stderr)

    benchmark = {
        "benchmark_meta": {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "inputs_requested": args.inputs,
            "inputs_resolved": dataset_paths,
            "runs": args.runs,
            "warmup_runs": args.warmup_runs,
            "max_rows_per_dataset": args.max_rows,
            "detection_mode": args.detection_mode,
            "ml_status": ml_status,
        },
        "datasets": dataset_reports,
        "overall_summary": _overall_summary(dataset_reports),
        "failures": failures,
    }

    if args.output:
        output_path = args.output
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join("reports", f"detector_benchmark_{ts}.json")

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(benchmark, f, indent=2)

    print(f"Benchmark completed. Output: {os.path.abspath(output_path)}")
    print(
        f"Datasets successful: {len(dataset_reports)}, failed: {len(failures)}, "
        f"overall_throughput={benchmark['overall_summary']['overall_throughput_logs_per_sec_weighted_mean']:.2f} logs/s"
    )

    return 0 if dataset_reports else 1


if __name__ == "__main__":
    raise SystemExit(main())
