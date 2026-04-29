import ast
import json
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}
REQUESTS_IMPORT_FROM_METHODS = HTTP_METHODS | {"request"}

DB_CONNECT_NAMES = {
    "connect",
    "create_engine",
}

DB_CLIENT_NAMES = {
    "MongoClient",
}

DB_MODULE_HINTS = {
    "psycopg2",
    "pymysql",
    "mysql",
    "sqlite3",
    "redis",
    "sqlalchemy",
    "asyncpg",
}


def _dotted_name(expr: ast.AST) -> Optional[str]:
    """
    Best-effort dotted name for simple Attribute/Name chains.
    Example: mysql.connector.connect -> "mysql.connector.connect"
    """
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = _dotted_name(expr.value)
        if base:
            return f"{base}.{expr.attr}"
    return None


def _extract_target_names(target: ast.AST) -> List[str]:
    """Extract simple variable names from assignment targets."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        out: List[str] = []
        for elt in target.elts:
            out.extend(_extract_target_names(elt))
        return out
    # Ignore Attribute/Subscript/etc. (obj.attr, d[k])
    return []


def _is_string_constant(expr: ast.AST) -> bool:
    return isinstance(expr, ast.Constant) and isinstance(expr.value, str)


def _expr_contains_name_from_taint(expr: ast.AST, taint_roots: Dict[str, Set[str]]) -> Set[str]:
    """
    Return the set of root variables tainted by this expression.
    If expression contains tainted variable names, we map them to their roots.
    """
    roots: Set[str] = set()
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in taint_roots:
            roots |= taint_roots[node.id]
    return roots


def _collect_requests_aliases(tree: ast.Module) -> Tuple[Set[str], Set[str]]:
    """
    Collect identifiers used to refer to requests functions/modules.
    """
    requests_aliases: Set[str] = {"requests"}
    requests_callables: Set[str] = set()

    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "requests":
                    requests_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module == "requests":
                for alias in node.names:
                    if alias.name in REQUESTS_IMPORT_FROM_METHODS:
                        requests_callables.add(alias.asname or alias.name)

    return requests_aliases, requests_callables


def _risk_rank(risk: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(risk, 0)


def _merge_record(dst: Dict, *, variable: str, used_in: str, risk: str, usage_line: int) -> None:
    if variable not in dst:
        dst[variable] = {
            "variable": variable,
            "used_in": used_in,
            "risk": risk,
            "usage_lines": [usage_line],
        }
        return

    rec = dst[variable]
    if _risk_rank(risk) > _risk_rank(rec.get("risk", "low")):
        rec["risk"] = risk

    # Keep used_in informative but bounded.
    if used_in not in rec.get("used_in", ""):
        if rec["used_in"] != used_in:
            rec["used_in"] = f"{rec['used_in']}; {used_in}"

    if usage_line not in rec.setdefault("usage_lines", []):
        rec["usage_lines"].append(usage_line)


def analyze_source(source: str, *, filename: str = "<source>") -> List[dict]:
    """
    Dataflow tracking (intra-file, lightweight).

    - Find string-literal assignments and mark them tainted ("root variables").
    - Propagate taint through simple assignments (aliases / f-string / +).
    - Detect whether tainted values are used in sensitive contexts:
        * requests calls with Authorization/auth usage
        * DB connection calls where credentials are passed
    """
    tree = ast.parse(source, filename=filename)
    requests_aliases, requests_callables = _collect_requests_aliases(tree)

    # var -> set(root vars)
    taint_roots: Dict[str, Set[str]] = {}
    # root -> record
    records: Dict[str, dict] = {}
    # root var -> list of definition lines encountered so far
    definitions: Dict[str, List[int]] = {}

    # We need a processing order to approximate "after definition".
    candidate_nodes: List[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.Call)):
            if hasattr(node, "lineno"):
                candidate_nodes.append(node)
    candidate_nodes.sort(key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0)))

    # Single left-to-right pass:
    # - add taint only when we encounter a tainted assignment
    # - flag sensitive usage only based on taint active at that point
    for node in candidate_nodes:
        usage_line = getattr(node, "lineno", None)
        if usage_line is None:
            continue

        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            if isinstance(node, ast.Assign):
                rhs = node.value
                targets = node.targets
            else:
                rhs = node.value
                targets = [node.target]

            for target in targets:
                for name in _extract_target_names(target):
                    if _is_string_constant(rhs):
                        # New root definition becomes active only at this line.
                        taint_roots[name] = {name}
                        definitions.setdefault(name, [])
                        if usage_line not in definitions[name]:
                            definitions[name].append(usage_line)
                        continue

                    roots = _expr_contains_name_from_taint(rhs, taint_roots)
                    if roots:
                        taint_roots[name] = taint_roots.get(name, set()) | roots

        elif isinstance(node, ast.Call):
            call = node

            call_roots: Set[str] = set()

            dotted_func = _dotted_name(call.func)

            # -----------------------------
            # Sensitive context #1: requests
            # -----------------------------
            is_requests_call = False
            if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
                if call.func.value.id in requests_aliases and call.func.attr in REQUESTS_IMPORT_FROM_METHODS:
                    is_requests_call = True
            elif isinstance(call.func, ast.Name):
                if call.func.id in requests_callables:
                    is_requests_call = True

            if is_requests_call:
                # 1) Authorization header dict usage
                used_authorization = False
                roots_in_auth: Set[str] = set()

                # headers=... in keyword args
                for kw in call.keywords:
                    if kw.arg not in {"headers", "auth"}:
                        continue
                    if kw.value is None:
                        continue

                    # headers={...}
                    if kw.arg == "headers" and isinstance(kw.value, ast.Dict):
                        for k, v in zip(kw.value.keys, kw.value.values):
                            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                                if k.value.lower() == "authorization":
                                    roots_in_auth |= _expr_contains_name_from_taint(v, taint_roots)
                                    used_authorization = True
                    # auth=...
                    else:
                        roots_in_auth |= _expr_contains_name_from_taint(kw.value, taint_roots)
                        if roots_in_auth:
                            used_authorization = True

                # Also support inline headers dict in positional args: requests.get(..., {"Authorization": key})
                if not used_authorization:
                    for arg in call.args:
                        if isinstance(arg, ast.Dict):
                            for k, v in zip(arg.keys, arg.values):
                                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                                    if k.value.lower() == "authorization":
                                        roots_in_auth |= _expr_contains_name_from_taint(v, taint_roots)
                                        used_authorization = True

                if roots_in_auth:
                    call_roots |= roots_in_auth
                    if used_authorization:
                        for r in roots_in_auth:
                            _merge_record(
                                records,
                                variable=r,
                                used_in="HTTP request",
                                risk="high",
                                usage_line=usage_line,
                            )

                else:
                    # Generic sensitive usage: tainted values are used in the request call somewhere.
                    roots_in_call = set()
                    for arg in list(call.args) + [kw.value for kw in call.keywords if kw.value is not None]:
                        roots_in_call |= _expr_contains_name_from_taint(arg, taint_roots)
                    if roots_in_call:
                        call_roots |= roots_in_call
                        for r in roots_in_call:
                            _merge_record(
                                records,
                                variable=r,
                                used_in="HTTP request",
                                risk="medium",
                                usage_line=usage_line,
                            )

            # -----------------------------
            # Sensitive context #2: DB connection
            # -----------------------------
            is_db_call = False
            if dotted_func:
                # e.g. psycopg2.connect, mysql.connector.connect, sqlalchemy.create_engine
                if dotted_func.endswith("connect") and any(m in dotted_func for m in DB_MODULE_HINTS):
                    is_db_call = True
                elif dotted_func.endswith("create_engine") and "sqlalchemy" in dotted_func:
                    is_db_call = True
                elif dotted_func.endswith("MongoClient"):
                    is_db_call = True

            # Handle direct names: MongoClient(...)
            if isinstance(call.func, ast.Name) and call.func.id in DB_CLIENT_NAMES:
                is_db_call = True

            if is_db_call:
                roots_in_db_call: Set[str] = set()
                for kw in call.keywords:
                    if kw.value is None:
                        continue
                    roots_in_db_call |= _expr_contains_name_from_taint(kw.value, taint_roots)

                for arg in call.args:
                    roots_in_db_call |= _expr_contains_name_from_taint(arg, taint_roots)

                if roots_in_db_call:
                    # Using tainted variables in a DB connect call is sensitive.
                    used_in = "DB connection"
                    risk = "high"
                    for r in roots_in_db_call:
                        _merge_record(
                            records,
                            variable=r,
                            used_in=used_in,
                            risk=risk,
                            usage_line=usage_line,
                        )

    # Clean up empty used_in records and ensure definitions + file info.
    out: List[dict] = []
    for var, rec in records.items():
        if not rec.get("used_in"):
            continue
        out.append(
            {
                "variable": var,
                "used_in": rec["used_in"],
                "risk": rec["risk"],
            }
        )

    # Stable ordering for tests/debugging
    out.sort(key=lambda r: (r["variable"], r["risk"]))
    return out


def _iter_python_files(paths: List[str]) -> List[Path]:
    files: List[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_file() and path.suffix == ".py":
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(path.rglob("*.py")))
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description="Dataflow tracking for sensitive contexts")
    parser.add_argument("paths", nargs="+", help="files or directories to analyze")
    parser.add_argument("--output", "-o", default=None, help="save results to this JSON file")
    args = parser.parse_args()

    all_records: List[dict] = []
    for f in _iter_python_files(args.paths):
        source = f.read_text(encoding="utf-8", errors="replace")
        all_records.extend(analyze_source(source, filename=str(f)))

    output = json.dumps(all_records, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"tracked {len(all_records)} sensitive variable usage(s), saved to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()

