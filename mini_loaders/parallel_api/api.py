from multi_process_job import Job, Supervisor
from uuid import uuid4
import os


def execute_jobs_in_parallel(job_entry_points):
    pipe_id = os.path.join("/tmp", str(uuid4()))
    if os.path.exists(pipe_id):
        os.remove(pipe_id)
    try:
        jobs = []
        for entry_point in job_entry_points:
            jobs.append(Job(pipe_id, entry_point))

        supervisor = Supervisor(pipe_id, jobs)

        supervisor.run()
    finally:
        if os.path.exists(pipe_id):
            os.remove(pipe_id)
