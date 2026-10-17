"""Worker loop: claim queued jobs and drive each through the pipeline.

Sequential by design (one job at a time): each job runs an LLM agent in a
sandboxed container, so v1 keeps a single in-flight job and relies on
docker-level resource limits rather than in-process concurrency. On an
empty queue the worker sleeps ``worker_poll_seconds`` (default 30) and
re-checks.

Startup runs :meth:`JobQueue.requeue_stale` so jobs left ``running`` by a
crashed previous worker are reclaimed (threshold: ``stale_job_seconds``,
default 1800 = 2x the harness timeout).

Graceful shutdown: SIGTERM/SIGINT set a stop flag. The current job is
finished (the pipeline and the docker timeout bound how long that can
take); the loop exits before claiming the next job. Install the handlers
with :meth:`install_signal_handlers` when running in the main thread.

The worker never raises out of :meth:`run_forever`: an unexpected failure
on one job fails that job in the queue and the loop continues.
"""

from __future__ import annotations

import logging
import signal
import time

from .pipeline import process_job
from .queue import Job, JobQueue, TransitionError

log = logging.getLogger(__name__)


class Worker:
    def __init__(
        self,
        settings: object,
        queue: JobQueue,
        *,
        backend: object | None = None,
        poll_interval: float | None = None,
        process: object = process_job,
        sleeper: object = time.sleep,
    ) -> None:
        self.settings = settings
        self.queue = queue
        self._backend = backend
        self.poll_interval = poll_interval or getattr(
            settings, "worker_poll_seconds", 30
        )
        self._process = process
        self._sleep = sleeper
        self._stop = False

    @property
    def backend(self) -> object:
        """Lazily build the DockerBackend so tests never touch docker."""

        if self._backend is None:
            from .docker_backend import DockerBackend

            self._backend = DockerBackend(self.settings)
        return self._backend

    def stop(self) -> None:
        self._stop = True

    def idle_loop(self) -> None:
        """Sleep until stopped; used when job secrets are missing.

        Keeps the process (and its signal handlers) alive so the service
        stays up and logs show why nothing is being processed, instead of
        crash-looping.
        """

        while not self._stop:
            self._sleep(self.poll_interval)

    def install_signal_handlers(self) -> None:
        def handler(signum: int, _frame: object) -> None:
            log.info("received signal %d; stopping after the current job",
                     signum)
            self.stop()

        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGINT, handler)

    def run_forever(self) -> None:
        requeued = self.queue.requeue_stale(
            getattr(self.settings, "stale_job_seconds", 1800)
        )
        if requeued:
            log.warning("requeued %d stale running job(s) on startup",
                        requeued)
        while not self._stop:
            job = self.queue.claim_next()
            if job is None:
                self._sleep(self.poll_interval)
                continue
            self._run_one(job)

    def _run_one(self, job: Job) -> None:
        payload = job.payload_dict()
        if payload is None:
            reason = "job has no stored payload (pre-migration row)"
            log.error("job %s: %s", job.id, reason)
            try:
                self.queue.transition(job.id, "failed", error=reason)
            except TransitionError:
                pass
            return
        log.info("processing job %s (%s)", job.id, job.package)
        try:
            self._process(
                job_id=job.id,
                payload=payload,
                settings=self.settings,
                queue=self.queue,
                backend=self.backend,
            )
        except Exception as exc:
            # process_job already transitions; this is the last-resort net
            # for bugs outside it. The loop must survive.
            log.exception("job %s crashed the pipeline: %s", job.id, exc)
            try:
                self.queue.transition(job.id, "failed", error=str(exc)[:512])
            except TransitionError:
                pass
