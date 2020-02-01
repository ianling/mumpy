import logging
import socket
from ssl import SSLContext, PROTOCOL_TLS
from threading import Thread

from mumpy.session import Session


class Server:
    def __init__(self, certfile, keyfile, keypassword=None, host='0.0.0.0', port=64738):
        self.running = True
        self.sessions = []
        self.channels = [{'name': 'Root'}]
        self._registered_users = []
        self._host = host
        self._port = port
        self._log = logging.getLogger(f'Murpy@{self._host}:{self._port}')
        self._certfile = certfile
        self._keyfile = keyfile
        self._keypassword = keypassword
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_context = SSLContext(PROTOCOL_TLS)
        if self._certfile is not None:
            ssl_context.load_cert_chain(self._certfile, keyfile=self._keyfile, password=self._keypassword)
        self._tcp_socket = ssl_context.wrap_socket(tcp_socket)
        self._tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_socket.bind((self._host, self._port))
        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_socket.bind((self._host, self._port))
        self._listen_tcp_thread = Thread(target=self._listen_tcp)
        self._listen_tcp_thread.start()
        self._listen_udp_thread = Thread(target=self._listen_udp)
        self._listen_udp_thread.start()
        self._log.info("Listening...")

    def _listen_tcp(self):
        self._tcp_socket.listen(socket.SOMAXCONN)
        while self.running:
            try:
                client_socket, address = self._tcp_socket.accept()
                client_socket.settimeout(60)
                session = Session(self, client_socket, address)
            except OSError:
                # socket closed; probably ran self.stop()
                self.running = False

    def _listen_udp(self):
        pass

    def _send_payload(self, message_type, payload, sessions=()):
        """
        Sends a message to the specified sessions. If no sessions are specified, sends the message to all sessions.

        Args:
            message_type(int): protocol message type defined in MessageType enum
            payload(protobuf message): the protobuf message object to send
            sessions(iterable): list of sessions to send the mssage to

        Returns:
            None
        """
        if len(sessions) == 0:
            sessions = self.sessions
        for session in sessions:
            try:
                session._send_payload(message_type, payload)
            except OSError:
                return False

    def add_user(self, session_object):
        """
        Adds a user to the list of users.

        Returns:
            int: the session ID of the new user
        """
        self.sessions.append(session_object)
        return len(self.sessions) - 1

    def is_alive(self):
        return self.running

    def stop(self):
        self.running = False
        self._tcp_socket.shutdown(socket.SHUT_RDWR)
        self._tcp_socket.close()
