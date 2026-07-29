#!/usr/bin/env python3
import argparse
import json
import os
import re
from glob import glob
from pathlib import Path
from typing import Any, Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def _resolve_inputs(patterns: List[str]) -> List[str]:
    files: List[str] = []
    for p in patterns:
        matches = sorted(glob(p))
        if matches:
            files.extend(matches)
        elif os.path.isfile(p):
            files.append(p)
    # Keep stable order, deduplicate
    uniq = []
    seen = set()
    for f in files:
        abs_f = os.path.abspath(f)
        if abs_f not in seen:
            seen.add(abs_f)
            uniq.append(abs_f)
    return uniq


def _load_report(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _dataset_name(report: Dict[str, Any], fallback_path: str) -> str:
    meta = report.get("evaluation_meta", {})
    input_csv = meta.get("input_csv_path")
    mode = (meta.get("detection_mode") or "").strip()
    if input_csv:
        name = Path(input_csv).stem
    else:
        name = Path(fallback_path).stem
    if mode:
        return f"{name} [{mode}]"
    return name


def _safe_slug(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", text.strip())
    return slug.strip("_") or "report"


def _plot_metric_comparison(
    reports: List[Tuple[str, Dict[str, Any]]],
    outdir: str,
    prefix: str = "",
) -> str:
    dataset_names = []
    means = {
        "accuracy": [],
        "precision": [],
        "recall": [],
        "f1": [],
    }
    lower = {k: [] for k in means}
    upper = {k: [] for k in means}
    has_ci = False

    for report_path, report in reports:
        name = _dataset_name(report, report_path)
        bm = report.get("binary_anomaly_metrics", {})
        ci = (report.get("binary_anomaly_ci") or {}).get("intervals") or {}
        dataset_names.append(name)
        for metric in means:
            value = float(bm.get(metric, 0.0))
            means[metric].append(value)
            ci_entry = ci.get(metric) or {}
            lo = float(ci_entry.get("low", value))
            hi = float(ci_entry.get("high", value))
            if hi > lo:
                has_ci = True
            lower[metric].append(max(0.0, value - lo))
            upper[metric].append(max(0.0, hi - value))

    x = list(range(len(dataset_names)))
    width = 0.2

    fig, ax = plt.subplots(figsize=(max(9, len(dataset_names) * 1.3), 5))
    ax.bar(
        [i - 1.5 * width for i in x],
        means["accuracy"],
        width=width,
        label="Accuracy",
        yerr=[lower["accuracy"], upper["accuracy"]] if has_ci else None,
        ecolor="#222222" if has_ci else None,
        capsize=3 if has_ci else 0,
    )
    ax.bar(
        [i - 0.5 * width for i in x],
        means["precision"],
        width=width,
        label="Precision",
        yerr=[lower["precision"], upper["precision"]] if has_ci else None,
        ecolor="#222222" if has_ci else None,
        capsize=3 if has_ci else 0,
    )
    ax.bar(
        [i + 0.5 * width for i in x],
        means["recall"],
        width=width,
        label="Recall",
        yerr=[lower["recall"], upper["recall"]] if has_ci else None,
        ecolor="#222222" if has_ci else None,
        capsize=3 if has_ci else 0,
    )
    ax.bar(
        [i + 1.5 * width for i in x],
        means["f1"],
        width=width,
        label="F1",
        yerr=[lower["f1"], upper["f1"]] if has_ci else None,
        ecolor="#222222" if has_ci else None,
        capsize=3 if has_ci else 0,
    )

    ax.set_ylim(0.0, 1.05)
    ax.set_ylabel("Score")
    title = "Detector Performance by Dataset"
    if has_ci:
        title += " (95% CI)"
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(dataset_names, rotation=25, ha="right")
    ax.grid(axis="y", linestyle=":", alpha=0.35)
    ax.legend(loc="lower right")
    fig.tight_layout()

    out_path = os.path.join(outdir, f"{prefix}metrics_comparison.png")
    fig.savefig(out_path, dpi=180)
    plt.close(fig)
    return out_path


def _plot_binary_confusion(
    report_path: str,
    report: Dict[str, Any],
    outdir: str,
    prefix: str = "",
) -> str:
    name = _dataset_name(report, report_path)
    bm = report.get("binary_anomaly_metrics", {})
    tp = int(bm.get("tp", 0))
    fp = int(bm.get("fp", 0))
    tn = int(bm.get("tn", 0))
    fn = int(bm.get("fn", 0))

    # Rows = true labels [normal, anomaly], Cols = predicted [normal, anomaly]
    matrix = [[tn, fp], [fn, tp]]
    labels = ["Normal", "Anomaly"]

    fig, ax = plt.subplots(figsize=(4.2, 4))
    im = ax.imshow(matrix, cmap="Blues")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    ax.set_title(f"Binary Confusion Matrix\n{name}")
    ax.set_xticks([0, 1], labels=labels)
    ax.set_yticks([0, 1], labels=labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")

    for r in range(2):
        for c in range(2):
            ax.text(c, r, str(matrix[r][c]), ha="center", va="center", color="black")

    fig.tight_layout()
    out_path = os.path.join(outdir, f"{prefix}{_safe_slug(name)}_binary_confusion.png")
    fig.savefig(out_path, dpi=180)
    plt.close(fig)
    return out_path


def _plot_severity_confusion(
    report_path: str,
    report: Dict[str, Any],
    outdir: str,
    prefix: str = "",
) -> str:
    name = _dataset_name(report, report_path)
    sev = report.get("severity_metrics", {})
    labels = sev.get("labels") or []
    matrix = sev.get("confusion_matrix") or []
    if not labels or not matrix:
        return ""

    n = len(labels)
    fig_size = max(5, min(12, 1.0 + 0.75 * n))
    fig, ax = plt.subplots(figsize=(fig_size, fig_size))
    im = ax.imshow(matrix, cmap="Oranges")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    ax.set_title(f"Severity Confusion Matrix\n{name}")
    ax.set_xticks(range(n), labels=labels, rotation=35, ha="right")
    ax.set_yticks(range(n), labels=labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")

    for r in range(n):
        for c in range(n):
            ax.text(c, r, str(matrix[r][c]), ha="center", va="center", color="black", fontsize=8)

    fig.tight_layout()
    out_path = os.path.join(outdir, f"{prefix}{_safe_slug(name)}_severity_confusion.png")
    fig.savefig(out_path, dpi=180)
    plt.close(fig)
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate visualization images from detector evaluation JSON report(s)."
    )
    parser.add_argument(
        "--inputs",
        nargs="+",
        required=True,
        help="One or more JSON report paths or glob patterns.",
    )
    parser.add_argument(
        "--outdir",
        default="reports/visualizations",
        help="Output directory for generated PNG files.",
    )
    parser.add_argument(
        "--prefix",
        default="",
        help="Optional output filename prefix, e.g. run_20260217_.",
    )
    args = parser.parse_args()

    report_files = _resolve_inputs(args.inputs)
    if not report_files:
        print("[ERROR] No report files matched the provided inputs.")
        return 1

    os.makedirs(args.outdir, exist_ok=True)
    reports = [(p, _load_report(p)) for p in report_files]

    generated: List[str] = []
    generated.append(_plot_metric_comparison(reports, args.outdir, prefix=args.prefix))
    for report_path, report in reports:
        generated.append(_plot_binary_confusion(report_path, report, args.outdir, prefix=args.prefix))
        sev_path = _plot_severity_confusion(report_path, report, args.outdir, prefix=args.prefix)
        if sev_path:
            generated.append(sev_path)

    # Preserve order and remove duplicates from printed output list.
    dedup_generated: List[str] = []
    seen = set()
    for path in generated:
        abs_path = os.path.abspath(path)
        if abs_path not in seen:
            seen.add(abs_path)
            dedup_generated.append(abs_path)

    print("Visualization complete. Files generated:")
    for path in dedup_generated:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
