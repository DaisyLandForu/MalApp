from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from malapp.evaluation.gold_expansion import (
    freeze_gold_expansion,
    gold_expansion_overview,
    load_frozen_gold_index,
    prepare_gold_expansion,
    save_gold_review,
)


class GoldExpansionTest(unittest.TestCase):
    def setUp(self) -> None:
        test_tmp = Path(__file__).resolve().parents[1] / ".test_tmp"
        test_tmp.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=test_tmp)
        self.data_dir = Path(self.temp.name) / "data"
        self.suite = self.data_dir / "evaluation" / "five_layer" / "suite-test"
        (self.suite / "layer1_model").mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _record(sample_id: str, label: str, *, official: bool) -> dict:
        return {
            "id": sample_id,
            "layer": "layer1_model",
            "track": "single_model_feature_only",
            "input": {
                "md5": sample_id,
                "app_name": f"应用-{sample_id[-2:]}",
                "package_name": f"pkg.{sample_id[-2:].lower()}",
            },
            "expected": {
                "verdict": label,
                "label_source": "expert" if official else "source_reference",
                "output_schema": {"required": ["verdict"]},
            },
            "models": ["model_a", "model_b"],
            "annotation_status": (
                "gold_from_frozen_validation"
                if official
                else "strict_source_reference_requires_two_expert_reviews"
            ),
            "label_tier": (
                "frozen_validation_gold"
                if official
                else "source_reference_requires_two_expert_reviews"
            ),
            "intended_use": (
                "release_gate" if official else "provisional_strict_release_diagnostic"
            ),
            "training_overlap": False,
        }

    def _write_suite(self, official: list[dict], pending: list[dict]) -> None:
        def write(path: Path, rows: list[dict]) -> None:
            path.write_text(
                "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
                encoding="utf-8",
            )

        write(
            self.suite / "layer1_model" / "model_release_holdout.jsonl",
            official + pending,
        )
        write(
            self.suite / "layer1_model" / "expert_gold_holdout.jsonl",
            official,
        )
        manifest = {
            "suite_id": "suite-test",
            "suite_dir": str(self.suite),
            "selection": {
                "release_holdout_count": len(official) + len(pending),
                "expert_gold_holdout_count": len(official),
            },
        }
        latest = self.data_dir / "evaluation" / "five_layer" / "latest.json"
        latest.write_text(json.dumps(manifest), encoding="utf-8")

    def test_prepare_500_is_stratified_and_hides_source_labels(self) -> None:
        official = [
            self._record(f"{index:032X}", "malicious", official=True)
            for index in range(1, 93)
        ] + [
            self._record(f"{index:032X}", "benign", official=True)
            for index in range(93, 96)
        ]
        pending = [
            self._record(f"{index:032X}", "malicious", official=False)
            for index in range(1000, 1700)
        ] + [
            self._record(f"{index:032X}", "benign", official=False)
            for index in range(2000, 2700)
        ]
        self._write_suite(official, pending)

        prepared = prepare_gold_expansion(target_total=500, data_dir=self.data_dir)
        self.assertEqual(405, prepared["candidate_count"])
        state = json.loads(
            (self.data_dir / "evaluation" / "gold_expansion" / "review_state.json").read_text(
                encoding="utf-8"
            )
        )
        labels = [item["source_reference_label"] for item in state["items"]]
        self.assertEqual(208, labels.count("malicious"))
        self.assertEqual(197, labels.count("benign"))

        public = gold_expansion_overview(
            data_dir=self.data_dir,
            reviewer="专家甲",
            limit=1,
        )["items"][0]
        self.assertNotIn("source_reference_label", public)
        self.assertNotIn("expected", public)
        self.assertNotIn("record", public)

    def test_two_blind_reviews_adjudication_and_freeze(self) -> None:
        official = [
            self._record("A" * 32, "malicious", official=True),
            self._record("B" * 32, "benign", official=True),
        ]
        pending = [
            self._record("C" * 32, "malicious", official=False),
            self._record("D" * 32, "benign", official=False),
        ]
        self._write_suite(official, pending)
        prepare_gold_expansion(target_total=4, data_dir=self.data_dir)
        items = gold_expansion_overview(
            data_dir=self.data_dir, reviewer="专家甲", limit=10
        )["items"]
        first_id, second_id = items[0]["id"], items[1]["id"]

        save_gold_review(
            data_dir=self.data_dir,
            sample_id=first_id,
            reviewer="专家甲",
            label="malicious",
        )
        first_for_second = gold_expansion_overview(
            data_dir=self.data_dir, reviewer="专家乙", limit=10
        )
        exposed = next(item for item in first_for_second["items"] if item["id"] == first_id)
        self.assertNotIn("independent_reviews", exposed)
        save_gold_review(
            data_dir=self.data_dir,
            sample_id=first_id,
            reviewer="专家乙",
            label="malicious",
        )

        save_gold_review(
            data_dir=self.data_dir,
            sample_id=second_id,
            reviewer="专家甲",
            label="malicious",
        )
        save_gold_review(
            data_dir=self.data_dir,
            sample_id=second_id,
            reviewer="专家乙",
            label="benign",
        )
        adjudication = gold_expansion_overview(
            data_dir=self.data_dir,
            reviewer="专家丙",
            role="adjudicate",
            limit=10,
        )
        disputed = next(item for item in adjudication["items"] if item["id"] == second_id)
        self.assertEqual(2, len(disputed["independent_reviews"]))
        save_gold_review(
            data_dir=self.data_dir,
            sample_id=second_id,
            reviewer="专家丙",
            label="benign",
            role="adjudicate",
        )
        ready = gold_expansion_overview(data_dir=self.data_dir, include_items=False)
        self.assertTrue(ready["ready_to_freeze"])
        self.assertEqual(4, ready["current_gold_count"])

        with patch(
            "malapp.evaluation.five_layer.generate_five_layer_suite",
            return_value={"suite_id": "v2-gold4-test"},
        ):
            frozen = freeze_gold_expansion(
                target_total=4,
                name="v2-gold4",
                data_dir=self.data_dir,
            )
        self.assertEqual(4, frozen["gold_set"]["target_total"])
        index = load_frozen_gold_index(self.data_dir)
        self.assertEqual(4, len(index))
        self.assertEqual("benign", index[second_id]["expected"]["verdict"])


if __name__ == "__main__":
    unittest.main()
