from __future__ import annotations

import os

from app_version import APP_VERSION
from runtime_data import resolve_data_dir

# Keep reports, caches and imported batches outside an individual release folder.
# The resolver migrates the newest legacy data directory once without overwriting it.
os.environ.setdefault("MALAPP_DATA_DIR", str(resolve_data_dir()))
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import atexit
from pathlib import Path
from threading import Thread


APP_NAME = "MalApp 智能研判平台"
HOST = "127.0.0.1"
PORT = int(os.getenv("MALAPP_PORT", "8765"))
_INSTANCE_MUTEX_HANDLE: int | None = None


def release_single_instance() -> None:
    global _INSTANCE_MUTEX_HANDLE
    if os.name == "nt" and _INSTANCE_MUTEX_HANDLE:
        try:
            import ctypes

            ctypes.windll.kernel32.CloseHandle(_INSTANCE_MUTEX_HANDLE)
        except Exception:
            pass
    _INSTANCE_MUTEX_HANDLE = None


def acquire_single_instance() -> bool:
    """Allow one desktop shell while keeping worker/evaluation modes independent."""
    global _INSTANCE_MUTEX_HANDLE
    if os.name != "nt" or _INSTANCE_MUTEX_HANDLE:
        return True
    import ctypes

    error_already_exists = 183
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    handle = kernel32.CreateMutexW(
        None, False, "Local\\MalApp_AgentTrace_LearningLoop_Desktop"
    )
    if not handle:
        boot_log("单实例互斥锁创建失败；继续启动")
        return True
    if kernel32.GetLastError() == error_already_exists:
        kernel32.CloseHandle(handle)
        boot_log("检测到桌面程序正在启动或运行；忽略重复启动")
        return False
    _INSTANCE_MUTEX_HANDLE = int(handle)
    atexit.register(release_single_instance)
    return True


def boot_log(message: str) -> None:
    try:
        path = install_root() / "desktop_boot.log"
        encoding = "utf-8" if path.exists() and path.stat().st_size else "utf-8-sig"
        with path.open("a", encoding=encoding) as handle:
            handle.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
    except OSError:
        pass


def bundle_root() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def install_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def prepare_data_dir() -> Path:
    data_dir = Path(os.environ.get("MALAPP_DATA_DIR") or resolve_data_dir()).expanduser().resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    seed_dir = bundle_root() / "data_seed"
    if not seed_dir.exists():
        seed_dir = bundle_root() / "data"
    for relative in ("schema.json", "field_mapping.json", "sample_conflict.json", "eval/best_params.json"):
        source = seed_dir / relative
        target = data_dir / relative
        if source.exists() and not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    return data_dir


def configure_external_model_runtime() -> Path | None:
    candidates = []
    configured = os.getenv("MALAPP_PYTHON_SITE_PACKAGES", "").strip()
    if configured:
        candidates.append(Path(configured).expanduser())
    for parent in (install_root(), *install_root().parents):
        candidates.append(parent / ".venv" / "Lib" / "site-packages")
        candidates.append(parent / "test1" / ".venv" / "Lib" / "site-packages")
    seen: set[str] = set()
    for site_packages in candidates:
        key = str(site_packages)
        if key in seen:
            continue
        seen.add(key)
        if not all(
            (site_packages / dependency).exists()
            for dependency in ("torch", "transformers", "accelerate")
        ):
            continue
        python_exe = site_packages.parents[1] / "Scripts" / "python.exe"
        if not python_exe.is_file():
            continue
        os.environ["MALAPP_EXTERNAL_MODEL_RUNTIME"] = str(site_packages.resolve())
        os.environ["MALAPP_EXTERNAL_PYTHON"] = str(python_exe.resolve())
        return site_packages.resolve()
    return None


def start_qwen_worker() -> subprocess.Popen | None:
    if str(os.getenv("MALAPP_USE_LOCAL_QWEN", "")).lower() not in {"1", "true", "yes", "y"}:
        return None
    python_text = os.getenv("MALAPP_EXTERNAL_PYTHON", "").strip()
    if not python_text:
        return None
    python_exe = Path(python_text)
    worker_script = bundle_root() / "local_qwen_worker.py"
    if not python_exe.is_file() or not worker_script.is_file():
        return None
    port = available_port(PORT + 100)
    worker_url = f"http://{HOST}:{port}"
    env = os.environ.copy()
    env["MALAPP_QWEN_WORKER_PORT"] = str(port)
    worker_log_path = install_root() / "qwen_worker.log"
    worker_log = worker_log_path.open("a", encoding="utf-8")
    process = subprocess.Popen(
        [str(python_exe), "-u", str(worker_script)],
        cwd=str(install_root()),
        env=env,
        stdout=worker_log,
        stderr=worker_log,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        wait_until_ready(worker_url, timeout=90.0, health_path="/health")
    except Exception as exc:
        boot_log(f"Qwen worker startup failed: {type(exc).__name__}: {exc}; log={worker_log_path}")
        process.terminate()
        worker_log.close()
        return None
    worker_log.close()
    os.environ["MALAPP_QWEN_WORKER_URL"] = worker_url
    return process


def available_port(preferred: int) -> int:
    with socket.socket() as sock:
        if sock.connect_ex((HOST, preferred)) != 0:
            return preferred
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


def wait_until_ready(
    url: str,
    timeout: float = 20.0,
    health_path: str = "/api/health",
    *,
    server_thread: Thread | None = None,
    server_errors: list[str] | None = None,
) -> None:
    deadline = time.time() + timeout
    last_error = ""
    while time.time() < deadline:
        if server_thread is not None and not server_thread.is_alive():
            detail = (server_errors or ["服务线程提前退出"])[-1]
            raise RuntimeError(f"本地服务启动失败：{detail}")
        try:
            with urllib.request.urlopen(f"{url}{health_path}", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError as exc:
            last_error = str(exc)
            time.sleep(0.2)
    suffix = f"；最后错误：{last_error}" if last_error else ""
    raise RuntimeError(f"本地服务启动超时（等待{timeout:.0f}秒）{suffix}")


def main() -> None:
    if not acquire_single_instance():
        return
    boot_log(f"启动桌面应用 v{APP_VERSION}")
    os.environ["MALAPP_DISABLE_LLM_RULE_FALLBACK"] = "1"
    data_dir = prepare_data_dir()
    boot_log(f"数据目录就绪: {data_dir}")
    configure_external_model_runtime()
    boot_log("外部模型运行时检查完成")
    qwen_worker = start_qwen_worker()
    boot_log(f"本地 Qwen 工作进程: {'已启动' if qwen_worker else '未启动'}")
    port = available_port(PORT)
    os.environ["MALAPP_HOST"] = HOST
    os.environ["MALAPP_PORT"] = str(port)
    os.environ["MALAPP_DATA_DIR"] = str(data_dir)
    bundled_xgb = bundle_root() / "training_artifacts" / "xgb_selected_20260616"
    if not bundled_xgb.exists():
        bundled_xgb = bundle_root() / "training_artifacts" / "xgb"
    if bundled_xgb.exists():
        os.environ["MALAPP_XGB_DIR"] = str(bundled_xgb)
    boot_log(f"XGBoost 运行目录: {os.getenv('MALAPP_XGB_DIR', '未配置')}")

    from run import main as serve

    # XGBoost is intentionally lazy-loaded by the first status/prediction
    # request. Importing it here delayed every desktop launch by 20+ seconds
    # and allocated hundreds of MB before the user started a judgement.
    boot_log("XGBoost 已配置为按需加载")

    boot_log("服务模块导入完成")
    server_errors: list[str] = []

    def serve_with_capture() -> None:
        try:
            serve()
        except BaseException as exc:
            import traceback

            detail = f"{type(exc).__name__}: {exc}"
            server_errors.append(detail)
            boot_log(f"服务线程异常退出: {detail}")
            boot_log(traceback.format_exc())

    server_thread = Thread(
        target=serve_with_capture, name="malapp-server", daemon=True
    )
    server_thread.start()
    boot_log(f"服务线程已启动: {HOST}:{port}")
    url = f"http://{HOST}:{port}"
    startup_timeout = max(
        20.0, float(os.getenv("MALAPP_STARTUP_TIMEOUT", "90") or 90)
    )
    try:
        wait_until_ready(
            url,
            timeout=startup_timeout,
            server_thread=server_thread,
            server_errors=server_errors,
        )
    except Exception as exc:
        boot_log(f"服务健康检查失败: {type(exc).__name__}: {exc}")
        raise
    boot_log("服务健康检查通过")

    if os.getenv("MALAPP_NO_WINDOW") == "1":
        while server_thread.is_alive():
            time.sleep(1)
        return

    try:
        import webview
    except ImportError as exc:
        raise RuntimeError("桌面窗口组件未正确安装") from exc

    webview.create_window(
        APP_NAME,
        url=url,
        width=1440,
        height=920,
        min_size=(1024, 700),
        resizable=True,
        text_select=True,
        confirm_close=False,
    )
    try:
        webview.start(gui="edgechromium", debug=False, private_mode=False)
    finally:
        if qwen_worker and qwen_worker.poll() is None:
            qwen_worker.terminate()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        import ctypes
        import traceback

        boot_log(f"启动失败: {type(exc).__name__}: {exc}")
        boot_log(traceback.format_exc())
        if os.getenv("MALAPP_NO_WINDOW") != "1":
            ctypes.windll.user32.MessageBoxW(0, str(exc), APP_NAME, 0x10)
        raise
