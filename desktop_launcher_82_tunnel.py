from __future__ import annotations

import os


os.environ["MALAPP_FORCE_TUNNEL_MODELS"] = "1"
os.environ["MALAPP_USE_SERVER_MODELS"] = "1"
os.environ["MALAPP_MODEL_A_API_URL"] = "http://127.0.0.1:10000/v1"
os.environ["MALAPP_MODEL_A_MODEL"] = "Qwen3.6-35B-A3B-FP8"
os.environ.setdefault("MALAPP_MODEL_A_API_KEY", "EMPTY")
os.environ["MALAPP_MODEL_B_API_URL"] = "http://127.0.0.1:18012/v1"
os.environ["MALAPP_MODEL_B_MODEL"] = "malapp-model-b"


from desktop_launcher import main


if __name__ == "__main__":
    main()
