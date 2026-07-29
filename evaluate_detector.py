#!/usr/bin/env python3
import argparse
import json
import sys

from src.backend.evaluation import evaluate_detector_csv, save_evaluation_report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate AI-Log-Guard detector metrics from a labeled CSV dataset."
    )
    parser.add_argument("--input", required=True, help="Path to labeled CSV input file.")
    parser.add_argument("--output", default=None, help="Optional path for JSON report output.")
    parser.add_argument("--log-column", default=None, help="Override log line column name.")
    parser.add_argument("--label-column", default=None, help="Override binary label column name.")
    parser.add_argument("--severity-column", default=None, help="Override severity label column name.")
    parser.add_argument("--require-ml", action="store_true", help="Fail evaluation if ML model/vectorizer is not active.")
    parser.add_argument("--max-rows", type=int, default=None, help="Optional row limit for quick evaluation.")
    parser.add_argument(
        "--detection-mode",
        default="hybrid",
        choices=["hybrid", "heuristic_only", "ml_only"],
        help="Detection mode for ablation: hybrid, heuristic_only, or ml_only.",
    )
    parser.add_argument(
        "--bootstrap-samples",
        type=int,
        default=400,
        help="Bootstrap resamples for CI estimation (set 0 to disable CI).",
    )
    parser.add_argument(
        "--ci-confidence-level",
        type=float,
        default=0.95,
        help="Confidence level for bootstrap CI (default: 0.95).",
    )
    parser.add_argument(
        "--ci-seed",
        type=int,
        default=42,
        help="Random seed for bootstrap CI.",
    )

    args = parser.parse_args()

    try:
        report = evaluate_detector_csv(
            args.input,
            log_column=args.log_column,
            label_column=args.label_column,
            severity_column=args.severity_column,
            require_ml=args.require_ml,
            max_rows=args.max_rows,
            detection_mode=args.detection_mode,
            bootstrap_samples=args.bootstrap_samples,
            ci_confidence_level=args.ci_confidence_level,
            ci_seed=args.ci_seed,
        )
        output_path = save_evaluation_report(report, args.output)
    except Exception as exc:
        print(f"[ERROR] Evaluation failed: {exc}", file=sys.stderr)
        return 1

    binary = report.get("binary_anomaly_metrics", {})
    binary_ci = report.get("binary_anomaly_ci", {})
    meta = report.get("evaluation_meta", {})
    ml_status = (meta.get("ml_status") or {})
    ci_intervals = (binary_ci.get("intervals") or {})
    acc_ci = ci_intervals.get("accuracy") or {}
    f1_ci = ci_intervals.get("f1") or {}

    print("Evaluation completed.")
    print(f"Output: {output_path}")
    print(f"Detection mode: {meta.get('detection_mode', args.detection_mode)}")
    print(f"Rows evaluated: {meta.get('rows_evaluated', 0)}")
    print(
        "ML status: "
        f"ready={ml_status.get('ml_ready', False)}, "
        f"sklearn={ml_status.get('sklearn_available', False)}, "
        f"model_loaded={ml_status.get('model_loaded', False)}, "
        f"vectorizer_loaded={ml_status.get('vectorizer_loaded', False)}, "
        f"rows_with_ai_flag={ml_status.get('rows_with_ai_flag', 0)}"
    )
    print(
        "Binary anomaly metrics: "
        f"accuracy={binary.get('accuracy', 0.0):.4f}, "
        f"precision={binary.get('precision', 0.0):.4f}, "
        f"recall={binary.get('recall', 0.0):.4f}, "
        f"f1={binary.get('f1', 0.0):.4f}"
    )
    if ci_intervals:
        print(
            "95% CI: "
            f"accuracy=[{acc_ci.get('low', 0.0):.4f}, {acc_ci.get('high', 0.0):.4f}], "
            f"f1=[{f1_ci.get('low', 0.0):.4f}, {f1_ci.get('high', 0.0):.4f}]"
        )

    # Compact JSON summary for easy copy/paste.
    print(
        json.dumps(
            {
                "detection_mode": meta.get("detection_mode", args.detection_mode),
                "binary_anomaly_metrics": binary,
                "binary_anomaly_ci": binary_ci,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
