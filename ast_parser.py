import ast
import json
import argparse
from pathlib import Path


def extract_assignments(filepath):
    """
    Parse a Python file with ast and extract all assignments where
    the assigned value is a string literal.

    Returns a list of:
        {"variable": <name>, "value": <string>, "line": <int>}
    """
    results = []
    path = Path(filepath)

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"couldn't read {filepath}: {e}")
        return results

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as e:
        print(f"syntax error in {filepath}: {e}")
        return results

    for node in ast.walk(tree):
        # simple assignment:  x = "value"
        if isinstance(node, ast.Assign):
            value_node = node.value

            # unwrap a single-element tuple on the right: x = ("value",)
            if isinstance(value_node, ast.Tuple) and len(value_node.elts) == 1:
                value_node = value_node.elts[0]

            if not isinstance(value_node, ast.Constant) or not isinstance(value_node.value, str):
                continue

            string_value = value_node.value

            # each target can itself be a tuple (a, b = ...) — flatten them
            for target in node.targets:
                for name in _extract_names(target):
                    results.append({
                        "variable": name,
                        "value": string_value,
                        "line": node.lineno,
                    })

        # annotated assignment:  x: str = "value"
        elif isinstance(node, ast.AnnAssign):
            if node.value is None:
                continue
            value_node = node.value
            if not isinstance(value_node, ast.Constant) or not isinstance(value_node.value, str):
                continue

            for name in _extract_names(node.target):
                results.append({
                    "variable": name,
                    "value": value_node.value,
                    "line": node.lineno,
                })

    return results


def _extract_names(target):
    """
    Yield all simple variable names from an assignment target.
    Handles plain names (x), tuples ((a, b)), and nested tuples.
    Attribute targets (obj.attr) and subscripts (d[k]) are skipped.
    """
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _extract_names(elt)
    # ast.Attribute / ast.Subscript — not simple variable names, skip


def scan_paths(paths):
    all_results = []
    for p in paths:
        p = Path(p)
        if p.is_file():
            all_results.extend(extract_assignments(p))
        elif p.is_dir():
            for f in p.rglob("*.py"):
                all_results.extend(extract_assignments(f))
        else:
            print(f"path not found: {p}")
    return all_results


def main():
    parser = argparse.ArgumentParser(
        description="AST-based parser: extract string assignments from Python files"
    )
    parser.add_argument("paths", nargs="+", help="files or directories to scan")
    parser.add_argument("--output", "-o", default=None, help="save results to this JSON file")
    args = parser.parse_args()

    results = scan_paths(args.paths)
    output = json.dumps(results, indent=2)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"found {len(results)} string assignment(s), saved to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
