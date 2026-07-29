#!/usr/bin/env python3
import argparse
import json
import os
from glob import glob
from pathlib import Path
from typing import Any, Dict, List, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def _resolve_inputs(patterns: List[str]) -> List[str]:
    files: List[str] = []
    for pattern in patterns:
        matches = sorted(glob(pattern))
        if matches:
            files.extend(matches)
        elif os.path.isfile(pattern):
            files.append(pattern)

    unique: List[str] = []
    seen = set()
    for item in files:
        abs_path = os.path.abspath(item)
        if abs_path not in seen:
            unique.append(abs_path)
            seen.add(abs_path)
    return unique


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def _report_tag(path: str) -> str:
    stem = Path(path).stem
    prefix = "detector_benchmark_"
    if stem.startswith(prefix):
        return stem[len(prefix) :]
    return stem


def _extract_rows(
    reports: List[Tuple[str, Dict[str, Any]]]
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    multi_report = len(reports) > 1

    for report_path, report in reports:
        tag = _report_tag(report_path)
        mode = ((report.get("benchmark_meta") or {}).get("detection_mode") or "").strip()
        for dataset in report.get("datasets", []):
            aggregate = dataset.get("aggregate", {})
            latency = aggregate.get("latency_ms", {})
            dataset_name = str(dataset.get("dataset_name") or Path(report_path).stem)
            base_label = f"{dataset_name} [{mode}]" if mode else dataset_name
            label = f"{base_label}\n({tag})" if multi_report else base_label

            rows.append(
                {
                    "label": label,
                    "dataset_name": dataset_name,
                    "tag": tag,
                    "detection_mode": mode or "hybrid",
                    "throughput_mean": float(aggregate.get("throughput_logs_per_sec_mean", 0.0)),
                    "throughput_std": float(aggregate.get("throughput_logs_per_sec_std", 0.0)),
                    "latency_mean": float(latency.get("mean", 0.0)),
                    "latency_p95": float(latency.get("p95", 0.0)),
                    "latency_p99": float(latency.get("p99", 0.0)),
                    "latency_std": float(latency.get("std", 0.0)),
                    "ai_flag_rate": float(aggregate.get("ai_flag_rate", 0.0)),
                }
            )

    return rows


def _plot_throughput(rows: List[Dict[str, Any]], outdir: str, prefix: str = "") -> str:
    labels = [row["label"] for row in rows]
    means = [row["throughput_mean"] for row in rows]
    stds = [row["throughput_std"] for row in rows]
    x = list(range(len(rows)))

    fig, ax = plt.subplots(figsize=(max(9, len(rows) * 1.3), 5))
    bars = ax.bar(
        x,
        means,
        yerr=stds,
        capsize=4,
        color="#2E86AB",
        edgecolor="#1B4F72",
        linewidth=0.6,
    )

    ax.set_title("Detector Throughput by Dataset")
    ax.set_ylabel("Logs / second")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.grid(axis="y", linestyle=":", alpha=0.35)

    for bar, value in zip(bars, means):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:.1f}",
            ha="center",
            va="bottom",
            fontsize=8,
        )

    fig.tight_layout()
    out_path = os.path.join(outdir, f"{prefix}benchmark_throughput_by_dataset.png")
    fig.savefig(out_path, dpi=180)
    plt.close(fig)
    return out_path


def _plot_latency(rows: List[Dict[str, Any]], outdir: str, prefix: str = "") -> str:
    labels = [row["label"] for row in rows]
    mean_vals = [row["latency_mean"] for row in rows]
    p95_vals = [row["latency_p95"] for row in rows]
    p99_vals = [row["latency_p99"] for row in rows]
    x = list(range(len(rows)))
    width = 0.25

    fig, ax = plt.subplots(figsize=(max(9, len(rows) * 1.4), 5))
    ax.bar([i - width for i in x], mean_vals, width=width, label="Mean", color="#5C946E")
    ax.bar(x, p95_vals, width=width, label="P95", color="#F0A202")
    ax.bar([i + width for i in x], p99_vals, width=width, label="P99", color="#D95D39")

    ax.set_title("Detector Latency by Dataset")
    ax.set_ylabel("Latency (ms)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.grid(axis="y", linestyle=":", alpha=0.35)
    ax.legend(loc="upper right")

    fig.tight_layout()
    out_path = os.path.join(outdir, f"{prefix}benchmark_latency_by_dataset.png")
    fig.savefig(out_path, dpi=180)
    plt.close(fig)
    return out_path


def _plot_ai_flag_rate(rows: List[Dict[str, Any]], outdir: str, prefix: str = "") -> str:
    labels = [row["label"] for row in rows]
    rates_percent = [row["ai_flag_rate"] * 100.0 for row in rows]
    x = list(range(len(rows)))

    fig, ax = plt.subplots(figsize=(max(9, len(rows) * 1.3), 4.5))
    bars = ax.bar(x, rates_percent, color="#7D53DE", edgecolor="#4A2D8A", linewidth=0.6)

    ax.set_title("AI Flag Rate by Dataset")
    ax.set_ylabel("Flag rate (%)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.grid(axis="y", linestyle=":", alpha=0.35)

    for bar, value in zip(bars, rates_percent):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:.2f}%",
            ha="center",
            va="bottom",
            fontsize=8,
        )

    fig.tight_layout()
    out_path = os.path.join(outdir, f"{prefix}benchmark_ai_flag_rate.png")
    fig.savefig(out_path, dpi=180)
    plt.close(fig)
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate visualization images from detector benchmark JSON report(s)."
    )
    parser.add_argument(
        "--inputs",
        nargs="+",
        required=True,
        help="One or more benchmark JSON paths or glob patterns.",
    )
    parser.add_argument(
        "--outdir",
        default="reports/visualizations",
        help="Output directory for PNG files.",
    )
    parser.add_argument(
        "--prefix",
        default="",
        help="Optional output filename prefix, e.g. run_20260217_.",
    )
    args = parser.parse_args()

    report_paths = _resolve_inputs(args.inputs)
    if not report_paths:
        print("[ERROR] No benchmark report files matched --inputs.")
        return 1

    reports: List[Tuple[str, Dict[str, Any]]] = []
    for path in report_paths:
        report = _load_json(path)
        if "datasets" not in report or "overall_summary" not in report:
            print(f"[WARN] Skipping non-benchmark JSON: {path}")
            continue
        reports.append((path, report))

    if not reports:
        print("[ERROR] No valid benchmark report content found.")
        return 1

    rows = _extract_rows(reports)
    if not rows:
        print("[ERROR] Benchmark report has no dataset rows to plot.")
        return 1

    os.makedirs(args.outdir, exist_ok=True)
    generated = [
        _plot_throughput(rows, args.outdir, prefix=args.prefix),
        _plot_latency(rows, args.outdir, prefix=args.prefix),
        _plot_ai_flag_rate(rows, args.outdir, prefix=args.prefix),
    ]

    print("Benchmark visualization complete. Files generated:")
    for path in generated:
        print(os.path.abspath(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
