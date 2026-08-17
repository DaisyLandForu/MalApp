"""Command-line entry point for the MalApp FastAPI server."""

from __future__ import annotations

import uvicorn

from apps.server.app import create_app
from apps.server.config import load_server_config


def main() -> None:
    config = load_server_config()
    uvicorn.run(
        create_app(config),
        host=config.host,
        port=config.port,
        server_header=False,
        access_log=True,
    )


if __name__ == "__main__":
    main()
