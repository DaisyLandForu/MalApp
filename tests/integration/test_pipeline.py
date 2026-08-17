import base64
import io
import unittest
import zipfile
from unittest.mock import patch

from malapp.agents.threat_intelligence import extract_network_indicators
from malapp.application.judgement import (
    DATA_DIR,
    EvidenceBlock,
    apply_xgb_agent_scores,
    extract_iocs,
    judge,
    load_json,
)
from malapp.data_import.preprocess import merge_network_packages, normalize_feature_record
from malapp.inference.local_qwen import parse_model_json
from malapp.orchestration.debate import (
    coerce_initial_schema_values,
    compact_evidence_for_llm,
    normalize_turn,
    placeholder_model_output,
    valid_closing_schema,
    valid_initial_schema,
)
from malapp.orchestration.decision import collaborative_decision, debate_confidence


class PipelineTest(unittest.TestCase):
    def test_closing_schema_allows_debate_stage_language(self):
        closing = {
            "verdict": "malicious",
            "score": 0.91,
            "risk_level": "high",
            "confidence": 0.88,
            "arguments": ["模型甲与模型乙均确认控制地址命中高风险情报"],
            "omissions": [],
            "evidence_refs": ["threat_intel"],
            "contradictions": ["对方质疑已由网络情报证据完成反驳"],
            "evidence_chain": ["模型甲证据与模型乙复核共同支持恶意结论"],
            "feature_relations": ["控制地址和高危权限共同提升恶意风险"],
            "accepted_corrections": ["接受对方对证据时效性的修正"],
            "discarded_claims": ["放弃缺少证据支持的仿冒推断"],
        }

        self.assertTrue(valid_closing_schema(closing))
        self.assertFalse(valid_initial_schema(closing))

    def test_debate_prompt_evidence_is_compacted_for_local_qwen(self):
        compacted = compact_evidence_for_llm(
            {
                "agent": "threat_intel",
                "claim": "网络指标命中" * 100,
                "score": 0.9,
                "confidence": 0.8,
                "evidence": ["domain=" + "a" * 1000 for _ in range(20)],
                "evidence_items": [
                    {
                        "evidence_type": "network_indicator",
                        "source_fields": ["domains", "ips"],
                        "source_values": ["domains=" + "b" * 1000 for _ in range(20)],
                        "direction": "supports_malicious",
                        "strength": 0.9,
                        "description": "desc" * 300,
                    }
                ],
                "missing_fields": ["x"] * 20,
            }
        )
        self.assertLessEqual(len(compacted["claim"]), 160)
        self.assertEqual(len(compacted["evidence"]), 8)
        self.assertLessEqual(len(compacted["evidence"][0]), 220)
        self.assertEqual(len(compacted["evidence_items"][0]["source_values"]), 6)
        self.assertLessEqual(len(compacted["evidence_items"][0]["description"]), 220)

    def test_network_package_merge_supports_repeated_geo_dicts(self):
        merged = merge_network_packages(
            [
                {
                    "iocs": [{"type": "domain", "value": "a.example"}],
                    "domains": ["a.example"],
                    "geo": {"country": "中国"},
                },
                {
                    "iocs": [{"type": "domain", "value": "a.example"}],
                    "domains": ["a.example", "b.example"],
                    "geo": {"city": "北京"},
                },
            ]
        )
        self.assertEqual(merged["domains"], ["a.example", "b.example"])
        self.assertEqual(len(merged["iocs"]), 1)
        self.assertEqual(merged["geo"], {"country": "中国", "city": "北京"})

    def test_qwen_set_style_arguments_are_repaired(self):
        parsed = parse_model_json(
            """{
              "verdict":"suspicious",
              "score":0.62,
              "risk_level":"medium",
              "arguments":{"应用签名信息缺失且无法建立可信发布者链路","控制地址命中高风险网络情报并具有远程控制特征"},
              "omissions":[],
              "evidence_refs":["static_analysis","threat_intel"],
              "confidence":0.71,
              "contradictions":[],
              "evidence_chain":["签名信息缺失与高风险控制地址共同降低样本可信度"],
              "feature_relations":["控制地址情报命中与恶意远程控制结论形成直接支持关系"]
            }"""
        )
        self.assertEqual(
            parsed["arguments"],
            ["应用签名信息缺失且无法建立可信发布者链路", "控制地址命中高风险网络情报并具有远程控制特征"],
        )
        self.assertTrue(valid_initial_schema(parsed))

    def test_initial_schema_values_are_coerced(self):
        parsed = coerce_initial_schema_values(
            {
                "verdict": "malicious",
                "score": "0.88",
                "risk_level": "high",
                "arguments": "control_url matches a confirmed high-risk intelligence indicator",
                "omissions": "",
                "evidence_refs": "threat_intel",
                "confidence": "0.72",
                "contradictions": "",
                "evidence_chain": "control_url intelligence match supports a high-risk conclusion",
                "feature_relations": "the observed domain relationship directly supports the C2 conclusion",
            }
        )
        self.assertEqual(
            parsed["arguments"],
            ["control_url matches a confirmed high-risk intelligence indicator"],
        )
        self.assertEqual(parsed["evidence_refs"], ["threat_intel"])
        self.assertTrue(valid_initial_schema(parsed))

    def test_model_verdict_is_aligned_with_calibrated_score(self):
        result = normalize_turn(
            {
                "verdict": "benign",
                "score": 0.91,
                "confidence": 0.88,
                "arguments": [{"description": "控制地址命中", "source_values": {"ioc_id": "IOC-1"}}],
                "evidence_refs": ["threat_intel"],
                "evidence_chain": [["控制地址命中", "高风险"]],
                "feature_relations": [],
                "contradictions": [],
            },
            '{"verdict":"benign","score":0.91}',
            {"score": 0.5, "verdict": "benign", "arguments": [], "evidence_refs": []},
        )
        self.assertEqual(result["verdict"], "malicious")
        self.assertEqual(result["arguments"], ["控制地址命中（ioc_id=IOC-1）"])
        self.assertEqual(result["evidence_chain"], ["控制地址命中，高风险"])
        self.assertLessEqual(result["confidence"], 0.6)
        self.assertTrue(result["contradictions"])

    def test_rule_fallback_has_no_llm_confidence(self):
        self.assertEqual(
            debate_confidence(
                {
                    "model_a": {"confidence": 0.8},
                    "model_b": {"confidence": 0.9},
                    "stages": [
                        {
                            "turns": [
                                {"backend": "local_qwen_fallback"},
                                {"backend": "rule"},
                            ]
                        }
                    ],
                }
            ),
            0.0,
        )

    def test_high_confidence_xgb_uses_full_debate_by_default(self):
        xgb_result = {
            "enabled": True,
            "version": "test",
            "probability": 0.97,
            "verdict": "malicious",
            "agent_scores": {},
            "engine_scores": {"engine_a": 0.1, "engine_b": 0.9, "engine_c": 0.95},
            "thresholds": {"benign_threshold": 0.16, "malicious_threshold": 0.82},
        }
        debate_result = {
            "execution_mode": "llm_evidence_verification",
            "debate_rounds": 0,
            "model_a": {"score": 0.82, "verdict": "malicious", "confidence": 0.78},
            "model_b": {"score": 0.91, "verdict": "malicious", "confidence": 0.84},
            "arbiter": {"score": 0.865, "verdict": "malicious", "rationale": "evidence verified"},
            "cross_examination": [],
            "providers": {},
        }
        with (
            patch("malapp.application.judgement.local_qwen_enabled", return_value=True),
            patch("malapp.data_import.preprocess.get_cached_report", return_value=None),
            patch("malapp.inference.xgboost.predict", return_value=xgb_result),
            patch("malapp.application.judgement.debate", return_value=debate_result) as debate_mock,
        ):
            report = judge(
                {
                    "sample_id": "xgb-fast-path-test",
                    "engine_a_score": 10,
                    "engine_b_score": 90,
                }
            )
        self.assertEqual(report["debate"]["execution_mode"], "llm_evidence_verification")
        self.assertEqual(report["debate"]["debate_rounds"], 0)
        debate_evidence, debate_config = debate_mock.call_args.args
        self.assertFalse(debate_config["verification_mode"])
        self.assertEqual(debate_config["xgb_prior"]["probability"], 0.97)
        self.assertEqual(len(debate_evidence), 4)
        self.assertNotIn("xgboost_prior", {item.agent for item in debate_evidence})
        # The learned prior and two model votes are high, but this fixture has
        # no native domain evidence. The guardrail must keep it in review.
        self.assertEqual(report["decision"]["verdict"], "suspicious")
        self.assertTrue(report["decision"]["review_required"])
        self.assertEqual(
            report["decision"]["fusion"]["mode"],
            "engine_c_internal_calibration_then_abc_wec",
        )
        self.assertIn("pipeline_weight", report["decision"]["fusion"])
        self.assertIn("component_thresholds", report["decision"]["fusion"])
        self.assertLess(report["decision"]["final_score"], 0.97)
        self.assertGreater(report["decision"]["final_score"], 0.75)

    def test_xgb_prior_does_not_overwrite_insufficient_agent_evidence(self):
        block = EvidenceBlock(
            agent="impersonation",
            claim="缺少仿冒检测字段，无法可靠判断。",
            evidence=["缺少正版资产和图标特征。"],
            confidence=0.0,
            missing_fields=["official_app_name", "official_icon"],
            score=0.0,
            evidence_items=[
                {
                    "evidence_type": "missing_feature",
                    "direction": "insufficient",
                    "strength": 0.0,
                }
            ],
            status="insufficient_evidence",
            rule_score=0.0,
        )
        updated = apply_xgb_agent_scores(
            [block],
            {"agent_scores": {"impersonation": 0.97}},
        )[0]
        self.assertEqual(0.0, updated.score)
        self.assertEqual(0.0, updated.rule_score)
        self.assertEqual(0.97, updated.ml_prior)
        self.assertEqual("insufficient_evidence", updated.status)
        self.assertIn("无法可靠判断", updated.claim)
        self.assertEqual("model_prior", updated.evidence_items[-1]["direction"])

    def test_component_disagreement_requests_review_without_overriding_wec(self):
        blocks = [
            EvidenceBlock(
                agent=agent,
                claim="证据不足",
                evidence=["关键字段缺失"],
                confidence=0.0,
                missing_fields=["feature"],
                score=0.0,
                status="insufficient_evidence",
                rule_score=0.0,
            )
            for agent in (
                "static_analysis",
                "threat_intel",
                "impersonation",
                "business_label",
            )
        ]
        decision = collaborative_decision(
            {"engine_a_score": 5, "engine_b_score": 5},
            {
                "model_a": {"confidence": 0.8},
                "model_b": {"confidence": 0.8},
                "arbiter": {
                    "score": 0.61,
                    "verdict": "suspicious",
                    "rationale": "模型证据不足，需复核",
                },
                "stages": [
                    {"turns": [{"backend": "openai_compatible"}]}
                ],
            },
            blocks,
            xgb_result={
                "probability": 0.1,
                "verdict": "benign",
                "thresholds": {
                    "benign_threshold": 0.16,
                    "malicious_threshold": 0.82,
                },
            },
        )
        self.assertEqual("benign", decision["verdict"])
        self.assertTrue(decision["review_required"])
        self.assertFalse(decision["fusion"]["policy"]["override_applied"])
        self.assertIn("arbiter_suspicious", decision["review_reasons"])

    def test_conflict_excel_fields_are_promoted_for_specialists(self):
        normalized, _ = normalize_feature_record(
            {
                "MD5": "A" * 32,
                "冲突类型": "强冲突（白 vs 恶意）",
                "应用名称_360": "nan",
                "类型_360": "研判白样本",
                "病毒名称_360": "未知",
                "score_360": "0",
                "应用名称_cm": "云众益",
                "类型_cm": "研判恶意样本",
                "病毒名称_cm": "A.Fraud.MoneyManageEG.a",
                "score_cm": "100",
            },
            register_fields=False,
        )
        self.assertEqual(normalized["app_name"], "云众益")
        self.assertEqual(normalized["virus_name"], "A.Fraud.MoneyManageEG.a")
        self.assertEqual(normalized["engine_a_label"], "benign")
        self.assertEqual(normalized["engine_b_label"], "malicious")
        self.assertEqual(normalized["engine_conflict"]["score_gap"], 100.0)

    def test_qwen_placeholder_echo_is_rejected(self):
        fallback = {"score": 0.42, "verdict": "benign"}
        self.assertTrue(
            placeholder_model_output(
                {
                    "score": 0.0,
                    "verdict": "malicious|suspicious|benign",
                    "question": "定向质疑",
                    "answer": "证据化回应",
                },
                '{"question":"定向质疑","answer":"证据化回应","score":0.0}',
                fallback,
                "directed_attack",
            )
        )

    def test_md5_and_virus_name_are_not_misclassified_as_network_iocs(self):
        indicators = extract_network_indicators(
            {
                "md5": "43924749302BB7A8AA3C601BCE3583BE",
                "virus_name": "A.Fraud.MoneyManageEG.a",
                "app_name": "云众益",
            }
        )
        self.assertEqual(indicators["domains"], [])
        self.assertEqual(indicators["ips"], [])
        self.assertEqual(indicators["urls"], [])
        self.assertEqual(
            extract_iocs(
                {
                    "md5": "43924749302BB7A8AA3C601BCE3583BE",
                    "virus_name": "A.Fraud.MoneyManageEG.a",
                }
            ),
            [],
        )

    def test_demo_sample_generates_traceable_report(self):
        sample = load_json(DATA_DIR / "sample_conflict.json")
        report = judge(sample)
        self.assertIn(report["decision"]["verdict"], {"malicious", "suspicious", "benign"})
        self.assertEqual(len(report["evidence_blocks"]), 4)
        self.assertGreaterEqual(report["decision"]["final_score"], 0)
        self.assertLessEqual(report["decision"]["final_score"], 1)
        self.assertIn("model_a", report["debate"])
        self.assertIn("engine_c", report["decision"]["weights"])

    def test_apk_static_analysis_is_merged_into_report(self):
        apk_bytes = io.BytesIO()
        dex = bytearray(128)
        dex[:8] = b"dex\n035\0"
        dex[32:36] = len(dex).to_bytes(4, "little")
        dex.extend(
            b"com.umeng.analytics android.permission.READ_PHONE_STATE "
            b"dalvik.system.DexClassLoader libjiagu"
        )
        with zipfile.ZipFile(apk_bytes, "w") as apk:
            apk.writestr("AndroidManifest.xml", b"package com.example.wallet android.permission.READ_PHONE_STATE")
            apk.writestr("classes.dex", bytes(dex))
            apk.writestr("lib/armeabi-v7a/libjiagu.so", b"shell")
            apk.writestr("META-INF/CERT.RSA", b"fake-cert")
            apk.writestr("META-INF/MANIFEST.MF", b"Name: classes.dex\nSHA-256-Digest: test\n")

        report = judge(
            {
                "sample_id": "apk-static-test",
                "apk_base64": base64.b64encode(apk_bytes.getvalue()).decode("ascii"),
                "engine_a_score": 50,
                "engine_b_score": 50,
                "force_engine_c": True,
            }
        )
        static_feedback = report["preprocess"]["static_feedback"]
        apk_analysis = report["preprocess"]["apk_analysis"]
        self.assertTrue(report["sample"]["packer"])
        self.assertEqual(report["sample"]["signature_status"], "valid")
        self.assertGreaterEqual(report["sample"]["sdk_risk"]["risk_summary"]["high"], 1)
        self.assertIn("static_trust", apk_analysis)
        self.assertIsNotNone(static_feedback["score"])

    def test_threat_intelligence_outputs_reputation_graph_and_family_match(self):
        report = judge(
            {
                "sample_id": "threat-intel-test",
                "package_name": "com.fake.wallet",
                "control_url": "https://c2-risk.example.net/api/checkin",
                "control_mailbox": "devops@fraud-team.example",
                "control_phone": "13800138000",
                "permissions": ["READ_SMS", "SYSTEM_ALERT_WINDOW"],
                "api_calls": ["DexClassLoader", "sendTextMessage"],
                "threat_intel_records": [
                    {
                        "indicator": "c2-risk.example.net",
                        "type": "domain",
                        "source": "internal_blacklist",
                        "risk": "malicious",
                        "confidence": 0.9,
                        "registered_by": "fraud-team",
                        "country": "ZZ",
                        "asn": "AS64512",
                        "tags": ["c2", "fraud"],
                        "related": ["13800138000", "devops@fraud-team.example"],
                    },
                    {
                        "indicator": "13800138000",
                        "type": "phone",
                        "source": "case_graph",
                        "risk": "suspicious",
                        "confidence": 0.7,
                        "related": ["other.fake.app"],
                    },
                ],
                "family_feature_library": [
                    {
                        "family": "FraudWallet",
                        "features": {
                            "permissions": ["READ_SMS", "SYSTEM_ALERT_WINDOW"],
                            "api_calls": ["DexClassLoader", "sendTextMessage"],
                            "package_name": "com.fake.wallet",
                        },
                    }
                ],
                "engine_a_score": 50,
                "engine_b_score": 50,
                "force_engine_c": True,
            }
        )
        intel = report["preprocess"]["threat_intelligence"]
        self.assertGreaterEqual(intel["reputation"]["aggregate_risk"], 0.9)
        self.assertTrue(intel["social_graph"]["team_signals"]["shared_entity_count"] >= 1)
        self.assertEqual(intel["family_attribution"]["attributed_family"], "FraudWallet")
        self.assertGreaterEqual(intel["summary"]["risk_score"], 0.9)
        threat_block = next(block for block in report["evidence_blocks"] if block["agent"] == "threat_intel")
        self.assertGreaterEqual(threat_block["score"], 0.9)

    def test_impersonation_analysis_matches_official_assets(self):
        report = judge(
            {
                "sample_id": "impersonation-test",
                "app_name": "Secure Wal1et",
                "package_name": "com.secure.wa11et",
                "icon_hash": "a" * 64,
                "icon_text": "Secure Wallet",
                "developer_signature": "untrusted-signature",
                "official_app_assets": [
                    {
                        "brand": "Secure Wallet",
                        "app_name": "Secure Wallet",
                        "package_name": "com.secure.wallet",
                        "icon_hash": "a" * 64,
                        "icon_text": "Secure Wallet",
                        "developer_signature": "official-signature",
                    }
                ],
                "engine_a_score": 50,
                "engine_b_score": 50,
                "force_engine_c": True,
            }
        )
        analysis = report["preprocess"]["impersonation_analysis"]
        self.assertEqual(analysis["official_asset_match"]["asset_count"], 1)
        self.assertEqual(analysis["official_asset_match"]["best_match"]["brand"], "Secure Wallet")
        self.assertGreaterEqual(analysis["visual_similarity"]["best_match"]["icon_similarity"], 0.99)
        self.assertTrue(analysis["semantic_distance"]["best_match"]["tamper_tags"])
        self.assertGreaterEqual(analysis["assessment"]["impersonation_probability"], 0.8)
        impersonation_block = next(block for block in report["evidence_blocks"] if block["agent"] == "impersonation")
        self.assertGreaterEqual(impersonation_block["score"], 0.8)

    def test_business_label_chain_variant_and_agent_schema_validation(self):
        report = judge(
            {
                "sample_id": "business-label-test",
                "app_name": "Fast Loan",
                "package_name": "com.fast.loan.update",
                "permissions": ["READ_SMS", "READ_CONTACTS", "READ_PHONE_STATE"],
                "control_url": "https://c2-loan-risk.example.net/upload",
                "download_url": "https://fake-loan.example.net/app.apk",
                "certificate_status": "self_signed",
                "certificate_valid_to": "2025-01-01",
                "version_name": "v1.2.3.4-patch",
                "release_history": ["1.0.0", "1.1.0", "1.2.3.4"],
                "virus_name": "Android/FakeLoan",
                "fraud_family": "loan_fraud",
                "engine_a_score": 50,
                "engine_b_score": 50,
                "force_engine_c": True,
            }
        )
        business = report["preprocess"]["business_label_analysis"]
        self.assertIn("金融诈骗-虚假贷款类", business["summary"]["business_labels"])
        self.assertGreaterEqual(len(business["harm_chain"]["stages"]), 4)
        self.assertEqual(business["variant_assessment"]["variant_label"], "high_confidence_variant")
        validation = report["preprocess"]["agent_output_validation"]
        self.assertTrue(validation["auto_repair"])
        self.assertEqual(len(validation["items"]), 4)
        for block in report["evidence_blocks"]:
            self.assertTrue(block["claim"])
            self.assertTrue(block["evidence"])
            self.assertGreaterEqual(block["confidence"], 0)
            self.assertLessEqual(block["confidence"], 1)

    def test_agent_runtime_concurrency_timeout_restart_and_degrade(self):
        report = judge(
            {
                "sample_id": "agent-runtime-test",
                "app_name": "Runtime Test",
                "package_name": "com.runtime.test",
                "engine_a_score": 50,
                "engine_b_score": 50,
                "force_engine_c": True,
                "agent_runtime_config": {
                    "max_workers": 4,
                    "default_timeout_ms": 200,
                    "agents": {
                        "static_analysis": {"timeout_ms": 20},
                        "threat_intel": {"timeout_ms": 200, "max_restarts": 1},
                    },
                },
                "agent_runtime_faults": {
                    "static_analysis": {"sleep_ms": 80},
                    "threat_intel": {"failures": 1},
                },
            }
        )
        runtime = report["preprocess"]["agent_runtime"]
        self.assertTrue(runtime["scheduler"]["concurrent"])
        self.assertEqual(runtime["agents"]["static_analysis"]["status"], "timeout")
        self.assertEqual(runtime["agents"]["threat_intel"]["restart_count"], 1)
        self.assertEqual(runtime["agents"]["threat_intel"]["status"], "completed")
        self.assertEqual(len(report["evidence_blocks"]), 4)
        static_block = next(block for block in report["evidence_blocks"] if block["agent"] == "static_analysis")
        self.assertEqual(static_block["score"], 0)
        self.assertIn("timeout", static_block["evidence"][0])
        self.assertEqual(report["degradation"]["status"], "degraded")
        self.assertTrue(report["decision"]["review_required"])

    def test_debate_state_machine_memory_metrics_and_model_config(self):
        report = judge(
            {
                "sample_id": "debate-flow-test",
                "app_name": "Secure Wallet Loan",
                "package_name": "com.secure.wallet.loan",
                "permissions": ["READ_SMS", "SYSTEM_ALERT_WINDOW"],
                "control_url": "https://c2-risk.example.net/api",
                "fake_app": True,
                "engine_a_score": 85,
                "engine_b_score": 30,
                "debate_model_config": {
                    "model_a": {"backend": "rule", "model": "local-qwen-a-placeholder"},
                    "model_b": {"backend": "rule", "model": "local-qwen-b-placeholder"},
                },
            }
        )
        debate = report["debate"]
        self.assertIn("directed_attack", debate["state_machine"]["phases"])
        self.assertIn("evidence_rebuttal", debate["state_machine"]["phases"])
        self.assertIn("arbiter_review", debate["state_machine"]["phases"])
        self.assertEqual(debate["state_machine"]["state"], "completed")
        self.assertEqual(len(debate["memory"]["stage_summaries"]), len(debate["stages"]))
        self.assertGreater(debate["metrics"]["token_usage"]["total_tokens"], 0)
        self.assertIn("evidence_rebuttal:1", debate["metrics"]["stage_latency_ms"])
        self.assertEqual(debate["providers"]["model_a"]["model"], "local-qwen-a-placeholder")
        self.assertEqual(debate["providers"]["model_b"]["model"], "local-qwen-b-placeholder")
        self.assertEqual(debate["model_b"]["model_backend"], "rule")
        self.assertIn("logic_trace", debate["arbiter"])

    def test_cross_challenge_rebuttal_convergence_and_final_calibration(self):
        report = judge(
            {
                "sample_id": "cross-challenge-test",
                "app_name": "Fast Loan Wallet",
                "package_name": "com.fast.loan.wallet",
                "permissions": ["READ_SMS", "READ_CONTACTS", "SYSTEM_ALERT_WINDOW"],
                "control_url": "https://c2-loan-risk.example.net/api",
                "fake_app": True,
                "engine_a_score": 92,
                "engine_b_score": 25,
                "debate_model_config": {
                    "max_attack_rounds": 3,
                    "min_attack_rounds": 2,
                    "convergence_score_threshold": 0.08,
                    "model_a": {"backend": "rule"},
                    "model_b": {"backend": "rule"},
                },
            }
        )
        debate = report["debate"]
        self.assertGreaterEqual(debate["debate_rounds"], 2)
        self.assertTrue(debate["convergence"]["history"])
        self.assertIn(debate["convergence"]["stop_reason"], {"score_convergence", "argument_convergence", "max_rounds"})
        attacks = [stage for stage in debate["stages"] if stage["phase"] == "directed_attack"]
        rebuttals = [stage for stage in debate["stages"] if stage["phase"] == "evidence_rebuttal"]
        self.assertGreaterEqual(len(attacks), 2)
        self.assertGreaterEqual(len(rebuttals), 2)
        self.assertTrue(any(turn.get("evidence_refs") for stage in rebuttals for turn in stage["turns"]))
        arbiter = debate["arbiter"]
        self.assertIn("final_summary", arbiter)
        self.assertIn("calibration", arbiter)
        self.assertIn("calibrated_score", arbiter["calibration"])
        self.assertIn("positions", arbiter["logic_trace"])
        self.assertGreaterEqual(arbiter["score"], 0)
        self.assertLessEqual(arbiter["score"], 1)

    def test_dynamic_three_engine_weighting_and_complete_decision_json(self):
        report = judge(
            {
                "sample_id": "dynamic-decision-test",
                "app_name": "Fake Loan Wallet",
                "package_name": "com.fake.loan.wallet",
                "signature_status": "invalid",
                "permissions": ["READ_SMS", "READ_CONTACTS", "SYSTEM_ALERT_WINDOW"],
                "control_url": "https://c2-risk.example.net/upload",
                "fake_app": True,
                "brand_similarity": 0.95,
                "fraud_family": "loan_fraud",
                "engine_a_score": 95,
                "engine_b_score": 15,
                "decision_params": {
                    "initial_weights": {"engine_a": 1.1, "engine_b": 0.9, "engine_c": 1.2},
                    "weight_min": 0.4,
                    "weight_max": 2.0,
                    "evidence_gain": 0.8,
                    "conflict_gain": 0.4,
                },
            }
        )
        decision = report["decision"]
        self.assertTrue(decision["key_evidence"])
        self.assertTrue(any(item["decisive"] for item in decision["key_evidence"]))
        self.assertGreater(decision["weights"]["engine_c"], 1.2)
        self.assertLess(decision["weights"]["engine_a"], 1.1)
        self.assertLess(decision["weights"]["engine_b"], 0.9)
        for weight in decision["weights"].values():
            self.assertGreaterEqual(weight, 0.4)
            self.assertLessEqual(weight, 2.0)
        self.assertTrue(decision["weight_adjustments"])
        self.assertEqual(len(decision["decision_trace"]), 5)
        self.assertIn("formula", decision["consensus"])
        self.assertIn("weighted_terms", decision)
        self.assertIn(decision["verdict"], {"malicious", "suspicious", "benign"})


if __name__ == "__main__":
    unittest.main()
