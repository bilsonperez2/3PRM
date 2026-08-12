from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "tprm",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_track_started=True,
    # Every scan task has app.core.config.scan_timeout_seconds-scoped provider
    # timeouts internally; this is a backstop so a stuck task can't wedge a
    # worker slot forever.
    task_time_limit=600,
    beat_schedule={
        # The tick is frequent; the batch size is what keeps load low. See
        # app.workers.tasks.enqueue_due_scans for why this isn't a single
        # weekly fire-everything job.
        "enqueue-due-scans": {
            "task": "scans.enqueue_due_scans",
            "schedule": settings.scheduler_tick_minutes * 60.0,
        },
        # Availability probes are far lighter than scans (one HEAD request per
        # vendor), so they run on their own much shorter cadence.
        "run-uptime-checks": {
            "task": "uptime.run_checks",
            "schedule": settings.uptime_check_interval_minutes * 60.0,
        },
    },
    timezone="UTC",
)
