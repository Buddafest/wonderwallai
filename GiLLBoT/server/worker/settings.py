"""
GiLLBoT — ARQ Worker Settings
Configure the arq background task worker.

Run with:
    python -m arq server.worker.settings.WorkerSettings
"""

from __future__ import annotations

import logging
import os

from arq.connections import RedisSettings

from server.worker.tasks.sequence_runner import run_sequence_step
from server.worker.tasks.send_email import send_email_task
from server.worker.tasks.import_csv import import_csv_task

logger = logging.getLogger("gillbot.worker")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


class WorkerSettings:
    """
    ARQ worker configuration.
    All async functions in `functions` are registered as available tasks.
    """

    # Registered task functions
    functions = [
        run_sequence_step,
        send_email_task,
        import_csv_task,
    ]

    # Redis connection
    redis_settings = RedisSettings.from_dsn(REDIS_URL)

    # Worker tuning
    max_jobs = 10
    job_timeout = 300       # 5 minutes max per job
    keep_result = 3600      # Keep results for 1 hour
    retry_jobs = True
    max_tries = 3

    # Cron jobs — defined in scheduler.py
    # cron_jobs = [...]

    on_startup = None
    on_shutdown = None
