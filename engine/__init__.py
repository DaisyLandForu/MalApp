"""Local MVP engine for malicious APP judgement workflows."""

import importlib


def __getattr__(name: str):
    if name == "xgb_runtime":
        return importlib.import_module(".xgb_runtime", __name__)
    raise AttributeError(name)
