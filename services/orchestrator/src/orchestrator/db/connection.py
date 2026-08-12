from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg import Connection

from orchestrator.config import OrchestratorConfig


class Database:
    def __init__(self, config: OrchestratorConfig):
        self._database_url = config.database_url

    @contextmanager
    def connection(self) -> Iterator[Connection]:
        conn = psycopg.connect(self._database_url)
        try:
            yield conn
        finally:
            conn.close()