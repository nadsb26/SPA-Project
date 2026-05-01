import csv
import json
from pathlib import Path
from dataclasses import dataclass
 
from credential_scanner import scan_paths as regex_scan
from pipeline import run_pipeline
 
 
@dataclass
class Metrics:
    tp: int = 0 # true positives — we flagged it and it really was a secret
    fp: int = 0 # false positives — we flagged it but it wasn't a secret
    fn: int = 0 # false negatives — we missed a real secret
 
    @property
    def precision(self) -> float:
        # out of everything flagged, how many were actually secrets
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0
 
    @property
    def recall(self) -> float:
        # out of all real secrets, how many were caught
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0
 
    @property
    def f1(self) -> float:
        # balances precision and recall
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0
 
    def __str__(self) -> str:
        return (
            f" Precision : {self.precision:.3f}\n"
            f" Recall : {self.recall:.3f}\n"
            f" F1-score : {self.f1:.3f}\n"
            f" TP={self.tp}  FP={self.fp}  FN={self.fn}"
        )
 
 
def compute_metrics(predictions: list[dict], ground_truth: list[dict]) -> Metrics:
    # match predictions to ground truth by (file, line)
    # anything predicted that isn't in ground truth = false positive
    # anything in ground truth that wasn't predicted = false negative
    pred_set = {
        (str(Path(p["file"])), int(p["line"]), p.get("value", ""))
        for p in predictions
        if p.get("file") and p.get("line")
    }
    true_secret_set = {
        (str(Path(g["file"])), int(g["line"]), g.get("value", ""))
        for g in ground_truth
        if g.get("is_secret") in (True, "true", "True", "1", 1)
    }
 
    tp = len(pred_set & true_secret_set)
    fp = len(pred_set - true_secret_set)
    fn = len(true_secret_set - pred_set)
 
    return Metrics(tp=tp, fp=fp, fn=fn)
 
def load_ground_truth_json(path: str) -> list[dict]:
    # load ground truth labels from a JSON file
    return json.loads(Path(path).read_text(encoding="utf-8"))
 
def load_ground_truth_csv(path: str) -> list[dict]:
    # load ground truth labels from a CSV file
    # expects columns: file, line, is_secret
    records = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            records.append({
                "file" : row["file"],
                "line" : int(row["line"]),
                "is_secret": row["is_secret"].strip().lower() in ("true", "1", "yes"),
            })
    return records
 
def run_ablation_study(
    paths: list[str],
    ground_truth: list[dict],
    verbose: bool = True,
) -> dict[str, Metrics]:
    # runs all three versions of the pipeline and compares their scores
    # V1 = regex only, V2 = regex + AST + dataflow, V3 = everything including LLM
    results: dict[str, Metrics] = {}
 
    if verbose:
        print("\n" + "=" * 50)
        print("V1 — Regex + Keyword Scanner only")
        print("=" * 50)
    v1_findings = regex_scan(paths)
    results["V1"] = compute_metrics(v1_findings, ground_truth)
    if verbose:
        print(results["V1"])
 
    if verbose:
        print("\n" + "=" * 50)
        print("V2 — Regex + AST + Dataflow (no LLM)")
        print("=" * 50)
    v2_findings = run_pipeline(paths, use_llm=False)
    results["V2"] = compute_metrics(v2_findings, ground_truth)
    if verbose:
        print(results["V2"])
 
    if verbose:
        print("\n" + "=" * 50)
        print("V3 — Full pipeline (with LLM)")
        print("=" * 50)
    v3_all = run_pipeline(paths, use_llm=True)
    # remove anything the LLM is confident is not a real secret
    v3_findings = [f for f in v3_all if f.get("is_real_secret") is not False]
    results["V3"] = compute_metrics(v3_findings, ground_truth)
    if verbose:
        print(results["V3"])
 
    if verbose:
        _print_summary(results)
 
    return results
 
def _print_summary(results: dict[str, Metrics]) -> None:
    print("\n" + "=" * 50)
    print("ABLATION STUDY SUMMARY")
    print("=" * 50)
    print(f"{'Version':<10} {'Precision':>10} {'Recall':>8} {'F1':>8}")
    print("-" * 40)
    for version, m in results.items():
        print(f"{version:<10} {m.precision:>10.3f} {m.recall:>8.3f} {m.f1:>8.3f}")
    print()
 
if __name__ == "__main__":
    import argparse
 
    parser = argparse.ArgumentParser(description="Evaluate and run ablation study")
    parser.add_argument("paths", nargs="+", help="files or directories to scan")
    parser.add_argument("--ground-truth", "-g", required=True,
                        help="path to ground-truth JSON or CSV file")
    parser.add_argument("--format", choices=["json", "csv"], default="json",
                        help="ground truth file format")
    args = parser.parse_args()
 
    gt = (load_ground_truth_json(args.ground_truth) if args.format == "json"
          else load_ground_truth_csv(args.ground_truth))
 
    run_ablation_study(args.paths, gt)
 