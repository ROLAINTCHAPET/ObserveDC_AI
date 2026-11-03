"""Règle d'isolation (SAD §6), vérifiée en CI : le module agent n'importe jamais executor ;
seul guardrail peut appeler executor."""
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "observia"
ALLOWED_EXECUTOR_IMPORTERS = {"guardrail", "executor"}


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def violations() -> list[str]:
    found = []
    for path in ROOT.rglob("*.py"):
        package = path.relative_to(ROOT).parts[0]
        if package in ALLOWED_EXECUTOR_IMPORTERS or package == "tests":
            continue
        for name in imported_modules(path):
            if name == "executor" or name.startswith("executor."):
                found.append(f"{path.relative_to(ROOT)} importe {name}")
    return found


if __name__ == "__main__":
    problems = violations()
    for p in problems:
        print(f"VIOLATION : {p}")
    sys.exit(1 if problems else 0)
