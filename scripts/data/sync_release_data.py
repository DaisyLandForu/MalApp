from __future__ import annotations

import argparse
import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

TABLES = (
    "feature_registry",
    "import_batches",
    "batch_items",
    "sample_features",
    "sample_tasks",
    "report_cache",
    "judgements",
    "agent_traces",
    "reward_records",
    "batch_jobs",
    "batch_job_items",
    "human_reviews",
    "manual_labels",
)
MUTABLE_STATE_TABLES = {
    "import_batches",
    "batch_items",
    "sample_tasks",
    "report_cache",
    "batch_jobs",
    "batch_job_items",
}


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def online_backup(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(source)) as source_conn, closing(
        sqlite3.connect(target)
    ) as target_conn:
        source_conn.backup(target_conn)


def table_names(conn: sqlite3.Connection, schema: str = "main") -> set[str]:
    return {
        str(row[0])
        for row in conn.execute(
            f"SELECT name FROM {quote_identifier(schema)}.sqlite_master WHERE type='table'"
        )
    }


def table_columns(conn: sqlite3.Connection, schema: str, table: str) -> list[str]:
    return [
        str(row[1])
        for row in conn.execute(
            f"PRAGMA {quote_identifier(schema)}.table_info({quote_identifier(table)})"
        )
    ]


def merge_snapshot(snapshot: Path, target: Path) -> dict[str, object]:
    conn = sqlite3.connect(target, timeout=60)
    conn.execute("PRAGMA busy_timeout=60000")
    conn.execute("ATTACH DATABASE ? AS source_db", (str(snapshot),))
    source_tables = table_names(conn, "source_db")
    target_tables = table_names(conn)
    result: dict[str, object] = {"tables": {}}
    try:
        conn.execute("BEGIN IMMEDIATE")
        for table in TABLES:
            if table not in source_tables:
                continue
            if table not in target_tables:
                create_sql = conn.execute(
                    "SELECT sql FROM source_db.sqlite_master WHERE type='table' AND name=?",
                    (table,),
                ).fetchone()
                if not create_sql or not create_sql[0]:
                    continue
                conn.execute(str(create_sql[0]))
                target_tables.add(table)
            source_columns = table_columns(conn, "source_db", table)
            target_columns = set(table_columns(conn, "main", table))
            columns = [column for column in source_columns if column in target_columns]
            if not columns:
                continue
            quoted_table = quote_identifier(table)
            quoted_columns = ",".join(quote_identifier(column) for column in columns)
            before = int(conn.execute(f"SELECT COUNT(*) FROM main.{quoted_table}").fetchone()[0])
            conflict = "REPLACE" if table in MUTABLE_STATE_TABLES else "IGNORE"
            conn.execute(
                f"INSERT OR {conflict} INTO main.{quoted_table} ({quoted_columns}) "
                f"SELECT {quoted_columns} FROM source_db.{quoted_table}"
            )
            after = int(conn.execute(f"SELECT COUNT(*) FROM main.{quoted_table}").fetchone()[0])
            result["tables"][table] = {"before": before, "after": after, "added": after - before}
        conn.commit()
        result["integrity"] = conn.execute("PRAGMA integrity_check").fetchone()[0]
        result["foreign_key_issues"] = len(conn.execute("PRAGMA foreign_key_check").fetchall())
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.execute("DETACH DATABASE source_db")
        conn.close()
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Safely merge one MalApp release database into another.")
    parser.add_argument("source", type=Path)
    parser.add_argument("target", type=Path)
    parser.add_argument("--backup-dir", type=Path, required=True)
    args = parser.parse_args()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    source_snapshot = args.backup_dir / f"source_snapshot_{stamp}.db"
    target_backup = args.backup_dir / f"target_before_sync_{stamp}.db"
    online_backup(args.source, source_snapshot)
    online_backup(args.target, target_backup)
    result = merge_snapshot(source_snapshot, args.target)
    result.update(
        {
            "source_snapshot": str(source_snapshot.resolve()),
            "target_backup": str(target_backup.resolve()),
        }
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
