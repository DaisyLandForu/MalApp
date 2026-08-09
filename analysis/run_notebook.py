"""Minimal offline notebook executor for this reproducible capacity model.

The bundled workspace runtime does not include nbformat/nbclient, so this runner
executes code cells sequentially in one namespace and writes captured stdout
back to the notebook.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import traceback
from pathlib import Path


def main(path_text: str) -> None:
    path = Path(path_text)
    notebook = json.loads(path.read_text(encoding="utf-8"))
    namespace: dict[str, object] = {}
    execution_count = 0

    for cell in notebook["cells"]:
        if cell.get("cell_type") != "code":
            continue
        execution_count += 1
        stdout = io.StringIO()
        outputs: list[dict[str, object]] = []
        try:
            with contextlib.redirect_stdout(stdout):
                exec("".join(cell.get("source", [])), namespace, namespace)
        except Exception:
            outputs.append(
                {
                    "output_type": "error",
                    "ename": sys.exc_info()[0].__name__,
                    "evalue": str(sys.exc_info()[1]),
                    "traceback": traceback.format_exc().splitlines(),
                }
            )
        text = stdout.getvalue()
        if text:
            outputs.insert(
                0,
                {
                    "output_type": "stream",
                    "name": "stdout",
                    "text": text.splitlines(keepends=True),
                },
            )
        cell["execution_count"] = execution_count
        cell["outputs"] = outputs
        if any(output.get("output_type") == "error" for output in outputs):
            path.write_text(
                json.dumps(notebook, ensure_ascii=False, indent=1), encoding="utf-8"
            )
            raise RuntimeError(f"Notebook failed in cell {execution_count}")

    path.write_text(json.dumps(notebook, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Executed {execution_count} code cells: {path}")


if __name__ == "__main__":
    main(sys.argv[1])
