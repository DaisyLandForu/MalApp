from __future__ import annotations

import os
import sys
from pathlib import Path


os.environ.pop("MALAPP_FORCE_TUNNEL_MODELS", None)
os.environ["MALAPP_USE_SERVER_MODELS"] = "1"
os.environ["MALAPP_USE_LOCAL_QWEN"] = "0"
os.environ["MALAPP_MODEL_A_API_URL"] = "http://10.0.11.55:10000/v1"
os.environ["MALAPP_MODEL_A_MODEL"] = "Qwen3.6-35B-A3B-FP8"
os.environ.setdefault("MALAPP_MODEL_A_API_KEY", "EMPTY")
os.environ["MALAPP_MODEL_B_API_URL"] = "http://10.0.11.82:18012/v1"
os.environ["MALAPP_MODEL_B_MODEL"] = "malapp-model-b"
os.environ.setdefault("MALAPP_MODEL_B_API_KEY", "EMPTY")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--five-layer-worker":
        from engine.five_layer_workflows import worker_main

        raise SystemExit(worker_main(Path(sys.argv[2])))
    if len(sys.argv) >= 3 and sys.argv[1] == "--five-layer-eval":
        from tools.evaluation_cli import parser

        arguments = parser().parse_args(sys.argv[2:])
        arguments.func(arguments)
        raise SystemExit(0)
    from desktop_launcher import APP_NAME, boot_log, main

    try:
        main()
    except Exception as exc:
        import traceback

        boot_log(f"启动失败: {type(exc).__name__}: {exc}")
        boot_log(traceback.format_exc())
        if os.getenv("MALAPP_NO_WINDOW") != "1" and os.name == "nt":
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                0,
                f"{exc}\n\n详细诊断已写入 desktop_boot.log。",
                APP_NAME,
                0x10,
            )
        raise SystemExit(1)
