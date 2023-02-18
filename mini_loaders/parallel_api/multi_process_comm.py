import socket
import select
from consts import CONSTS
import struct
from uuid import uuid4
import json


class MESSAGE_TYPES(object):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2


class Protocol(object):
    @staticmethod
    def recv_message(sock, deserialize=False):
        message_size = sock.recv(struct.calcsize(CONSTS.MESSAGE_MAX_SIZE))
        message_size = struct.unpack("!{}".format(CONSTS.MESSAGE_MAX_SIZE), message_size)[0]
        message = sock.recv(message_size)
        if deserialize:
            return json.loads(message)
        return message

    @staticmethod
    def send_message(sock, message):
        size = struct.pack("!{}".format(CONSTS.MESSAGE_MAX_SIZE), len(message))
        sock.send(size)
        sock.send(message)

    @staticmethod
    def get_client_hello_message():
        return Protocol.get_message(message_type=MESSAGE_TYPES.CLIENT_HELLO)

    @staticmethod
    def get_server_hello_message(mark_id):
        return Protocol.get_message(message_type=MESSAGE_TYPES.SERVER_HELLO, data={"mark_id": mark_id})

    @staticmethod
    def get_message(message_type, data=None):
        message = {"message_type": message_type, "data": data}
        return json.dumps(message)


class MultiProcessServerComm(object):
    def __init__(self, pipe_id):
        self.pipe_id = pipe_id
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(CONSTS.MAX_SOCK_TIMEOUT)
        self.socket.bind(self.pipe_id)
        self.socket.listen(4096)
        self.clients = []
        self.marked_clients = {}
        self.pending_messages = {}
        self.handle_message_from_client = None

    def get_mark_id(self, sock):
        for mark_id, s in self.marked_clients.items():
            if s == sock:
                return mark_id

    def handshake(self, client):
        message = Protocol.recv_message(client, deserialize=True)
        assert message["message_type"] == MESSAGE_TYPES.CLIENT_HELLO
        mark_id = self.mark_client(client)
        server_hello = Protocol.get_server_hello_message(mark_id)
        Protocol.send_message(client, server_hello)
        self.clients.append(client)

    def handle_rlist(self, rlist):
        for sock in rlist:
            if sock is self.socket:
                new_client, address = self.socket.accept()
                self.handshake(new_client)
            else:
                message = Protocol.recv_message(sock, deserialize=True)
                if not self.handle_message_from_client:
                    raise NotImplementedError()
                mark_id = self.get_mark_id(sock)
                if not mark_id:
                    raise Exception("Mark id is none: {}".format(self.marked_clients))
                self.handle_message_from_client(message, self.get_mark_id(sock))

    def handle_wlist(self, wlist):
        for sock in wlist:
            messages = self.pending_messages.get(sock, [])
            for message in messages:
                Protocol.send_message(sock, message)
            self.pending_messages[sock] = []

    def handle(self):
        rlist, wlist, _ = select.select(self.clients + [self.socket], self.clients, [],
                                        CONSTS.SELECT_TIMEOUT)

        self.handle_rlist(rlist)
        self.handle_wlist(wlist)

    def push_message_to_client(self, message, mark_id):
        if mark_id not in self.marked_clients:
            raise Exception("Client {} not marked yet !".format(mark_id))

        sock = self.marked_clients[mark_id]
        if sock not in self.pending_messages:
            self.pending_messages[sock] = []

        self.pending_messages[sock].append(message)
        self.handle()

    def mark_client(self, sock):
        mark_id = str(uuid4())
        if sock in self.marked_clients.values():
            raise Exception("Socket already marked")
        else:
            self.marked_clients[mark_id] = sock

        return mark_id


class MultiProcessClientComm(object):
    def __init__(self, pipe_id):
        self.pipe_id = pipe_id
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(CONSTS.MAX_SOCK_TIMEOUT)
        self.mark_id = None
        self.pending_messages = []
        self.handle_message_from_server = None
        self.did_handshake = False

    def interrupt(self):
        self.interrupted = True

    def handshake(self):
        if self.did_handshake:
            return
        self.socket.connect(self.pipe_id)
        Protocol.send_message(self.socket, Protocol.get_client_hello_message())
        message = Protocol.recv_message(self.socket, deserialize=True)
        assert message["message_type"] == MESSAGE_TYPES.SERVER_HELLO, "Error got: {}".format(
            message["message_type"]
        )
        self.mark_id = message["data"]["mark_id"]
        self.did_handshake = True

    def handle(self):
        self.handshake()
        rlist, wlist, _ = select.select([self.socket], [self.socket], [], CONSTS.MAX_SOCK_TIMEOUT)

        if self.socket in rlist:
            self._handle_message_from_server()
        if self.socket in wlist:
            self._handle_message_to_server()

    def _handle_message_from_server(self):
        message = Protocol.recv_message(self.socket, deserialize=True)
        if not self.handle_message_from_server:
            raise NotImplementedError()
        self.handle_message_from_server(message)

    def _handle_message_to_server(self):
        for message in self.pending_messages:
            Protocol.send_message(self.socket, message)
        self.pending_messages = []

    def push_message_to_server(self, message):
        self.pending_messages.append(message)
        self.handle()
