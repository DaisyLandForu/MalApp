from __future__ import annotations

import argparse
import json
from pathlib import Path

AGENTS = ("static_analysis", "threat_intel", "impersonation", "business_label")
ROOT = Path(__file__).resolve().parents[2]


def require_dependencies():
    try:
        import torch
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
            Trainer,
            TrainingArguments,
        )
    except ImportError as exc:
        raise SystemExit(
            "缺少 SFT 依赖。请在有 GPU 的训练环境安装：\n"
            "pip install torch transformers peft accelerate bitsandbytes"
        ) from exc
    return {
        "torch": torch,
        "LoraConfig": LoraConfig,
        "get_peft_model": get_peft_model,
        "prepare_model_for_kbit_training": prepare_model_for_kbit_training,
        "AutoModelForCausalLM": AutoModelForCausalLM,
        "AutoTokenizer": AutoTokenizer,
        "BitsAndBytesConfig": BitsAndBytesConfig,
        "Trainer": Trainer,
        "TrainingArguments": TrainingArguments,
    }


class JsonlChatDataset:
    def __init__(self, path: Path, tokenizer, max_length: int, torch_module):
        self.records = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.torch = torch_module

    def __len__(self):
        return len(self.records)

    def __getitem__(self, index):
        messages = self.records[index]["messages"]
        prompt_messages = messages[:-1]
        full_text = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=False
        )
        prompt_text = self.tokenizer.apply_chat_template(
            prompt_messages, tokenize=False, add_generation_prompt=True
        )
        encoded = self.tokenizer(
            full_text,
            truncation=True,
            max_length=self.max_length,
            padding=False,
        )
        prompt_ids = self.tokenizer(
            prompt_text,
            truncation=True,
            max_length=self.max_length,
            padding=False,
        )["input_ids"]
        labels = list(encoded["input_ids"])
        labels[: min(len(prompt_ids), len(labels))] = [-100] * min(
            len(prompt_ids), len(labels)
        )
        return {
            "input_ids": self.torch.tensor(encoded["input_ids"], dtype=self.torch.long),
            "attention_mask": self.torch.tensor(
                encoded["attention_mask"], dtype=self.torch.long
            ),
            "labels": self.torch.tensor(labels, dtype=self.torch.long),
        }


class CausalCollator:
    def __init__(self, tokenizer, torch_module):
        self.tokenizer = tokenizer
        self.torch = torch_module

    def __call__(self, features):
        max_len = max(len(item["input_ids"]) for item in features)
        batch = {"input_ids": [], "attention_mask": [], "labels": []}
        for item in features:
            padding = max_len - len(item["input_ids"])
            batch["input_ids"].append(
                self.torch.cat(
                    [
                        item["input_ids"],
                        self.torch.full(
                            (padding,), self.tokenizer.pad_token_id, dtype=self.torch.long
                        ),
                    ]
                )
            )
            batch["attention_mask"].append(
                self.torch.cat(
                    [
                        item["attention_mask"],
                        self.torch.zeros(padding, dtype=self.torch.long),
                    ]
                )
            )
            batch["labels"].append(
                self.torch.cat(
                    [
                        item["labels"],
                        self.torch.full((padding,), -100, dtype=self.torch.long),
                    ]
                )
            )
        return {key: self.torch.stack(value) for key, value in batch.items()}


def main():
    parser = argparse.ArgumentParser(description="四智能体独立 LoRA/QLoRA SFT")
    parser.add_argument("--agent", required=True, choices=AGENTS)
    parser.add_argument("--model", required=True, help="本地模型路径或 Hugging Face 模型名")
    parser.add_argument("--output", default="")
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--grad-accum", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=2e-4)
    parser.add_argument("--max-length", type=int, default=2048)
    parser.add_argument("--qlora", action="store_true")
    args = parser.parse_args()

    deps = require_dependencies()
    torch = deps["torch"]
    data_dir = ROOT / "training_artifacts" / "sft" / args.agent
    output_dir = (
        Path(args.output)
        if args.output
        else ROOT / "training_artifacts" / "sft_models" / args.agent
    )
    tokenizer = deps["AutoTokenizer"].from_pretrained(
        args.model, trust_remote_code=True
    )
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token

    quantization = None
    if args.qlora:
        if not torch.cuda.is_available():
            raise SystemExit("QLoRA 需要 CUDA GPU。当前环境未检测到 CUDA。")
        quantization = deps["BitsAndBytesConfig"](
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
    model = deps["AutoModelForCausalLM"].from_pretrained(
        args.model,
        trust_remote_code=True,
        quantization_config=quantization,
        torch_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
        device_map="auto" if torch.cuda.is_available() else None,
    )
    if args.qlora:
        model = deps["prepare_model_for_kbit_training"](model)
    lora = deps["LoraConfig"](
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    )
    model = deps["get_peft_model"](model, lora)
    train_data = JsonlChatDataset(
        data_dir / "train.jsonl", tokenizer, args.max_length, torch
    )
    val_data = JsonlChatDataset(
        data_dir / "val.jsonl", tokenizer, args.max_length, torch
    )
    training_args = deps["TrainingArguments"](
        output_dir=str(output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.learning_rate,
        warmup_ratio=0.03,
        weight_decay=0.01,
        logging_steps=10,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        bf16=torch.cuda.is_available() and torch.cuda.is_bf16_supported(),
        fp16=torch.cuda.is_available() and not torch.cuda.is_bf16_supported(),
        report_to="none",
        remove_unused_columns=False,
    )
    trainer = deps["Trainer"](
        model=model,
        args=training_args,
        train_dataset=train_data,
        eval_dataset=val_data,
        data_collator=CausalCollator(tokenizer, torch),
    )
    trainer.train()
    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))
    print(f"{args.agent} SFT 完成：{output_dir}")


if __name__ == "__main__":
    main()
