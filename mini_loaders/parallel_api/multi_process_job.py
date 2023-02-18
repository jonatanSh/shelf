from multiprocessing import Process
from multi_process_comm import MultiProcessClientComm, MultiProcessServerComm, Protocol
import logging
import time
from consts import CONSTS


class Messages(object):
    INTERRUPT = 3
    EXITED = 4


class Job(Process):
    def __init__(self, endpoint, entry_point):
        self.comm = MultiProcessClientComm(pipe_id=endpoint)
        self.comm.handle_message_from_server = self.handle_message_from_server
        self.interrupt = False
        self.executed = False
        self.entry_point = entry_point
        self.signaled_terminated = False
        super(Job, self).__init__()

    def handle_message_from_server(self, message):
        message_type = message["message_type"]
        if message_type == Messages.INTERRUPT:
            self.interrupt = True

    def run(self):
        while not self.interrupt:
            self.comm.handle()
            self._job_execute()
        self.signal_terminated()

    def _job_execute(self):
        if self.executed:
            return
        self.executed = True
        self.job_execute()

    def job_execute(self):
        try:
            self.entry_point()
        except Exception as error:
            logging.error("Job error: {}".format(error))
        finally:
            self.signal_terminated()

    def signal_terminated(self):
        if self.signaled_terminated:
            return
        self.comm.push_message_to_server(Protocol.get_message(Messages.EXITED))
        self.signaled_terminated = True


class Supervisor(object):
    def __init__(self, endpoint, jobs):
        self.comm = MultiProcessServerComm(pipe_id=endpoint)
        self.comm.handle_message_from_client = self.handle_message_from_client
        self.clients = {}
        self.interrupted = False
        self.jobs = jobs

    def handle_message_from_client(self, message, client_id):
        if client_id not in self.clients:
            self.clients[client_id] = []
        self.clients[client_id].append(message)

    def handle_messages(self):
        for client_id, messages in self.clients.items():
            for message in messages:
                if message['message_type'] == Messages.EXITED:
                    logging.info("Closing job: {}".format(client_id))
                    self.comm.push_message_to_client(Protocol.get_message(Messages.INTERRUPT), client_id)
                    del self.clients[client_id]

    def start_all_jobs(self):
        for job in self.jobs:
            job.start()

    def run(self):
        self.start_all_jobs()
        while len(self.clients) < len(self.jobs):
            try:
                if self.interrupted:
                    break
                self.comm.handle()
                time.sleep(0.1)
            except KeyboardInterrupt:
                self.terminate()

        while self.clients:
            try:
                self.comm.handle()
                self.handle_messages()
            except KeyboardInterrupt:
                self.terminate()

    def terminate_all_clients(self):
        logging.info("Terminating all jobs: {}".format(len(self.clients)))
        for client_id in self.clients:
            self.comm.push_message_to_client(
                Protocol.get_message(message_type=Messages.INTERRUPT),
                client_id
            )

        logging.info("Waiting for jobs to terminate properly")
        start = time.time()
        while len(self.clients) > 0:
            if time.time() - start > CONSTS.MAX_TERMINATION_TIMEOUT:
                self.force_terminate()
                return

    def force_terminate(self):
        logging.error("Client did not terminate on time, forcing terminate")
        for job in self.jobs:
            try:
                job.terminate()
            except:
                pass

    def terminate(self):
        self.interrupted = True
        self.terminate_all_clients()
