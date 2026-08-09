from __future__ import annotations

import unittest

from engine.validation_set import stratified_rows, summarize_app_judgements


class ValidationSetTest(unittest.TestCase):
    def test_full_judged_accuracy_excludes_review_from_denominator(self) -> None:
        rows = [
            {"md5": "A", "_gold_label": "malicious"},
            {"md5": "B", "_gold_label": "benign"},
            {"md5": "C", "_gold_label": "malicious"},
            {"md5": "D", "_gold_label": "benign"},
        ]
        reports = {
            "A": {"decision": {"verdict": "malicious"}},
            "B": {"decision": {"verdict": "malicious"}},
            "C": {"decision": {"verdict": "suspicious"}},
        }

        summary = summarize_app_judgements(rows, reports)

        self.assertEqual(3, summary["total"])
        self.assertEqual(1, summary["correct"])
        self.assertEqual(1, summary["incorrect"])
        self.assertEqual(1, summary["review"])
        self.assertEqual(0.5, summary["accuracy"])
        self.assertEqual({"malicious": 2, "benign": 1}, summary["labels"])

    def test_stratified_rows_mix_labels_without_randomness(self) -> None:
        rows = [
            *[{"md5": f"M{i}", "_gold_label": "malicious"} for i in range(8)],
            *[{"md5": f"B{i}", "_gold_label": "benign"} for i in range(2)],
        ]

        mixed = stratified_rows(rows)

        self.assertEqual(10, len(mixed))
        self.assertEqual({"malicious", "benign"}, {row["_gold_label"] for row in mixed[:5]})
        self.assertEqual(
            [row["md5"] for row in mixed],
            [row["md5"] for row in stratified_rows(rows)],
        )


if __name__ == "__main__":
    unittest.main()
