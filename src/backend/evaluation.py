import csv
import json
import os
import random
from collections import Counter, deque
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from src.backend.core_logic import CoreLogic, DETECTION_MODES, SKLEARN_AVAILABLE


DEFAULT_LOG_COLUMNS = ["log_line", "line", "message", "log", "raw_log", "text"]
DEFAULT_LABEL_COLUMNS = ["label", "is_anomaly", "anomaly", "ground_truth", "target", "y_true"]
DEFAULT_SEVERITY_COLUMNS = ["severity", "true_severity", "expected_severity", "label_severity"]


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _percentile(sorted_values: List[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]

    q = max(0.0, min(1.0, q))
    rank = (len(sorted_values) - 1) * q
    lo = int(rank)
    hi = min(lo + 1, len(sorted_values) - 1)
    if lo == hi:
        return sorted_values[lo]
    weight = rank - lo
    return sorted_values[lo] * (1.0 - weight) + sorted_values[hi] * weight


def _normalize_headers(headers: List[str]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for h in headers:
        mapping[h.strip().lower()] = h
    return mapping


def _resolve_column(
    headers: List[str],
    candidates: List[str],
    explicit_column: Optional[str] = None,
    required: bool = False,
) -> Optional[str]:
    normalized = _normalize_headers(headers)

    if explicit_column:
        key = explicit_column.strip().lower()
        if key in normalized:
            return normalized[key]
        if required:
            raise ValueError(f"Column '{explicit_column}' was not found in CSV headers: {headers}")
        return None

    for c in candidates:
        key = c.strip().lower()
        if key in normalized:
            return normalized[key]

    if required:
        raise ValueError(f"Could not resolve required column from candidates: {candidates}. CSV headers: {headers}")
    return None


def _parse_bool_label(value: Any) -> Optional[bool]:
    if value is None:
        return None

    text = str(value).strip().lower()
    if not text:
        return None

    true_vals = {
        "1",
        "true",
        "t",
        "yes",
        "y",
        "anomaly",
        "attack",
        "malicious",
        "positive",
        "pos",
    }
    false_vals = {
        "0",
        "false",
        "f",
        "no",
        "n",
        "normal",
        "benign",
        "negative",
        "neg",
    }

    if text in true_vals:
        return True
    if text in false_vals:
        return False
    return None


def _normalize_severity(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None

    mapping = {
        "critical": "Critical",
        "error": "Error",
        "warn": "Warn",
        "warning": "Warn",
        "info": "Info",
        "debug": "Debug",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "mlanomaly": "MLAnomaly",
        "ml anomaly": "MLAnomaly",
    }
    return mapping.get(text, str(value).strip().title())


def _severity_to_anomaly(severity: Optional[str]) -> Optional[bool]:
    if not severity:
        return None
    sev = severity.strip().lower()
    non_anomaly = {"info", "debug", "normal", "benign"}
    return sev not in non_anomaly


def _compute_binary_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, Any]:
    total = tp + fp + tn + fn
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    accuracy = _safe_div(tp + tn, total)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    npv = _safe_div(tn, tn + fn)
    fpr = _safe_div(fp, fp + tn)
    fnr = _safe_div(fn, fn + tp)
    balanced_accuracy = (recall + specificity) / 2.0

    return {
        "support_total": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": specificity,
        "npv": npv,
        "fpr": fpr,
        "fnr": fnr,
        "balanced_accuracy": balanced_accuracy,
    }


def _bootstrap_binary_confidence_intervals(
    pairs: List[Tuple[bool, bool]],
    *,
    confidence_level: float = 0.95,
    n_resamples: int = 400,
    seed: int = 42,
) -> Dict[str, Any]:
    if not pairs or n_resamples <= 0:
        return {
            "method": "bootstrap",
            "confidence_level": confidence_level,
            "n_resamples": 0,
            "seed": seed,
            "intervals": {},
        }

    n = len(pairs)
    metric_names = ["accuracy", "precision", "recall", "f1", "specificity", "balanced_accuracy"]
    samples: Dict[str, List[float]] = {name: [] for name in metric_names}
    rng = random.Random(seed)

    for _ in range(max(1, n_resamples)):
        tp = fp = tn = fn = 0
        for _ in range(n):
            true_anomaly, pred_anomaly = pairs[rng.randrange(n)]
            if true_anomaly and pred_anomaly:
                tp += 1
            elif not true_anomaly and pred_anomaly:
                fp += 1
            elif not true_anomaly and not pred_anomaly:
                tn += 1
            else:
                fn += 1

        m = _compute_binary_metrics(tp, fp, tn, fn)
        for name in metric_names:
            samples[name].append(float(m.get(name, 0.0)))

    low_q = (1.0 - confidence_level) / 2.0
    high_q = 1.0 - low_q
    intervals: Dict[str, Dict[str, float]] = {}
    for name in metric_names:
        vals = sorted(samples[name])
        low = _percentile(vals, low_q)
        high = _percentile(vals, high_q)
        intervals[name] = {
            "low": low,
            "high": high,
            "half_width": (high - low) / 2.0,
        }

    return {
        "method": "bootstrap",
        "confidence_level": confidence_level,
        "n_resamples": max(1, n_resamples),
        "seed": seed,
        "intervals": intervals,
    }


def _compute_multiclass_metrics(pairs: List[Tuple[str, str]]) -> Dict[str, Any]:
    if not pairs:
        return {"support_total": 0, "accuracy": 0.0, "labels": [], "per_class": [], "confusion_matrix": []}

    labels = sorted(set([t for t, _ in pairs] + [p for _, p in pairs]))
    support_total = len(pairs)
    correct = sum(1 for t, p in pairs if t == p)
    accuracy = _safe_div(correct, support_total)

    per_class: List[Dict[str, Any]] = []
    precisions: List[float] = []
    recalls: List[float] = []
    f1s: List[float] = []
    weighted_precision_sum = 0.0
    weighted_recall_sum = 0.0
    weighted_f1_sum = 0.0
    weighted_support_sum = 0

    for label in labels:
        tp = sum(1 for t, p in pairs if t == label and p == label)
        fp = sum(1 for t, p in pairs if t != label and p == label)
        fn = sum(1 for t, p in pairs if t == label and p != label)
        support = sum(1 for t, _ in pairs if t == label)

        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        f1 = _safe_div(2 * precision * recall, precision + recall)

        per_class.append(
            {
                "label": label,
                "support": support,
                "precision": precision,
                "recall": recall,
                "f1": f1,
            }
        )

        precisions.append(precision)
        recalls.append(recall)
        f1s.append(f1)
        weighted_precision_sum += precision * support
        weighted_recall_sum += recall * support
        weighted_f1_sum += f1 * support
        weighted_support_sum += support

    index_map = {label: idx for idx, label in enumerate(labels)}
    matrix = [[0 for _ in labels] for _ in labels]
    for true_label, pred_label in pairs:
        matrix[index_map[true_label]][index_map[pred_label]] += 1

    macro_precision = _safe_div(sum(precisions), len(precisions))
    macro_recall = _safe_div(sum(recalls), len(recalls))
    macro_f1 = _safe_div(sum(f1s), len(f1s))

    weighted_precision = _safe_div(weighted_precision_sum, weighted_support_sum)
    weighted_recall = _safe_div(weighted_recall_sum, weighted_support_sum)
    weighted_f1 = _safe_div(weighted_f1_sum, weighted_support_sum)

    return {
        "support_total": support_total,
        "accuracy": accuracy,
        "labels": labels,
        "per_class": per_class,
        "macro_avg": {
            "precision": macro_precision,
            "recall": macro_recall,
            "f1": macro_f1,
        },
        "weighted_avg": {
            "precision": weighted_precision,
            "recall": weighted_recall,
            "f1": weighted_f1,
        },
        "confusion_matrix": matrix,
    }


def build_evaluation_corelogic(require_ml: bool = False) -> CoreLogic:
    """
    Creates a CoreLogic instance in a minimal mode for offline detector evaluation.
    This does not start monitoring threads.
    """
    stats = {"rule_action_counts": Counter()}
    detector = CoreLogic(
        shared_stats=stats,
        log_queue=deque(maxlen=1),
        alert_queue=deque(maxlen=1),
        graph_data=deque(maxlen=1),
        speed_data=deque(maxlen=1),
    )
    if require_ml:
        ml_ready = bool(SKLEARN_AVAILABLE and detector.model is not None and detector.vectorizer is not None)
        if not ml_ready:
            raise ValueError(
                "ML is required but not ready. Ensure scikit-learn is installed and built-in "
                "model/vectorizer files are available."
            )
    return detector


def evaluate_detector_csv(
    input_csv_path: str,
    *,
    log_column: Optional[str] = None,
    label_column: Optional[str] = None,
    severity_column: Optional[str] = None,
    require_ml: bool = False,
    max_rows: Optional[int] = None,
    detection_mode: str = "hybrid",
    bootstrap_samples: int = 400,
    ci_confidence_level: float = 0.95,
    ci_seed: int = 42,
) -> Dict[str, Any]:
    """
    Evaluates the current detector on a labeled CSV file.

    Required data:
    - A log line column (default auto-detect from common names).
    - At least one ground-truth signal:
      - binary label column (e.g., label/is_anomaly), OR
      - severity column (anomaly inferred from severity when binary label missing).
    """
    with open(input_csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if not rows:
        raise ValueError(f"No rows found in CSV: {input_csv_path}")

    headers = reader.fieldnames or list(rows[0].keys())
    resolved_log_col = _resolve_column(headers, DEFAULT_LOG_COLUMNS, log_column, required=True)
    resolved_label_col = _resolve_column(headers, DEFAULT_LABEL_COLUMNS, label_column, required=False)
    resolved_sev_col = _resolve_column(headers, DEFAULT_SEVERITY_COLUMNS, severity_column, required=False)

    if not resolved_label_col and not resolved_sev_col:
        raise ValueError(
            "Could not find a ground-truth label column. Provide one of "
            f"{DEFAULT_LABEL_COLUMNS} or a severity column from {DEFAULT_SEVERITY_COLUMNS}."
        )

    mode = (detection_mode or "hybrid").strip().lower()
    if mode not in DETECTION_MODES:
        raise ValueError(f"Invalid detection_mode='{detection_mode}'. Allowed values: {sorted(DETECTION_MODES)}")

    detector = build_evaluation_corelogic(require_ml=require_ml)
    ml_status = {
        "require_ml": require_ml,
        "sklearn_available": bool(SKLEARN_AVAILABLE),
        "model_loaded": detector.model is not None,
        "vectorizer_loaded": detector.vectorizer is not None,
    }
    ml_status["ml_ready"] = bool(
        ml_status["sklearn_available"] and ml_status["model_loaded"] and ml_status["vectorizer_loaded"]
    )

    tp = fp = tn = fn = 0
    severity_pairs: List[Tuple[str, str]] = []
    binary_pairs: List[Tuple[bool, bool]] = []
    skip_reasons = Counter()
    processed = 0
    ai_flag_count = 0
    ai_score_positive_count = 0

    for idx, row in enumerate(rows, start=1):
        if max_rows is not None and processed >= max_rows:
            break

        raw_line = (row.get(resolved_log_col) or "").strip()
        if not raw_line:
            skip_reasons["missing_log_line"] += 1
            continue

        true_anomaly: Optional[bool] = None
        if resolved_label_col:
            true_anomaly = _parse_bool_label(row.get(resolved_label_col))

        true_severity = _normalize_severity(row.get(resolved_sev_col)) if resolved_sev_col else None
        if true_anomaly is None:
            true_anomaly = _severity_to_anomaly(true_severity)

        if true_anomaly is None:
            skip_reasons["missing_or_invalid_ground_truth"] += 1
            continue

        result = detector.detect_line_for_evaluation(raw_line, detection_mode=mode)
        if not result:
            skip_reasons["parse_failed"] += 1
            continue

        pred_anomaly = bool(result["predicted_anomaly"])
        pred_severity = _normalize_severity(result["predicted_severity"]) or "Info"
        if bool(result.get("ai_flag")):
            ai_flag_count += 1
        if float(result.get("ai_score", 0.0)) > 0.0:
            ai_score_positive_count += 1

        if true_anomaly and pred_anomaly:
            tp += 1
        elif not true_anomaly and pred_anomaly:
            fp += 1
        elif not true_anomaly and not pred_anomaly:
            tn += 1
        else:
            fn += 1

        binary_pairs.append((true_anomaly, pred_anomaly))
        if true_severity:
            severity_pairs.append((true_severity, pred_severity))

        processed += 1

    binary = _compute_binary_metrics(tp, fp, tn, fn)
    binary_ci = _bootstrap_binary_confidence_intervals(
        binary_pairs,
        confidence_level=ci_confidence_level,
        n_resamples=bootstrap_samples,
        seed=ci_seed,
    )
    severity = _compute_multiclass_metrics(severity_pairs)

    return {
        "evaluation_meta": {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "input_csv_path": os.path.abspath(input_csv_path),
            "resolved_columns": {
                "log_column": resolved_log_col,
                "label_column": resolved_label_col,
                "severity_column": resolved_sev_col,
            },
            "detection_mode": mode,
            "rows_total_in_csv": len(rows),
            "rows_evaluated": processed,
            "rows_skipped": int(sum(skip_reasons.values())),
            "skip_reasons": dict(skip_reasons),
            "max_rows_limit": max_rows,
            "ci_settings": {
                "enabled": bool(bootstrap_samples > 0),
                "method": "bootstrap",
                "confidence_level": ci_confidence_level,
                "n_resamples": max(1, bootstrap_samples) if bootstrap_samples > 0 else 0,
                "seed": ci_seed,
            },
            "ml_status": {
                **ml_status,
                "rows_with_ai_flag": ai_flag_count,
                "rows_with_ai_score_gt_zero": ai_score_positive_count,
            },
        },
        "binary_anomaly_metrics": binary,
        "binary_anomaly_ci": binary_ci,
        "severity_metrics": severity,
    }


def save_evaluation_report(report: Dict[str, Any], output_json_path: Optional[str] = None) -> str:
    if output_json_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_json_path = os.path.join("reports", f"detector_evaluation_{ts}.json")

    output_dir = os.path.dirname(output_json_path) or "."
    os.makedirs(output_dir, exist_ok=True)

    with open(output_json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return os.path.abspath(output_json_path)
