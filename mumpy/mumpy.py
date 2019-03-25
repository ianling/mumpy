from mumpy import mumble_pb2
from mumpy.channel import Channel
from mumpy.constants import ConnectionState, MessageType, EventType, AudioType, PROTOCOL_VERSION, \
    OS_VERSION_STRING, RELEASE_STRING, OS_STRING, PING_INTERVAL
from mumpy.event import Event
from mumpy.event_handler import EventHandler
from mumpy.mumblecrypto import MumbleCrypto
from mumpy.user import User
from mumpy.varint import VarInt

from ipaddress import IPv6Address
from ssl import SSLContext, PROTOCOL_TLS
from threading import Thread
from time import time, sleep
import logging
import queue
import select
import socket
import struct
import traceback
import wave


class Mumpy:
    def __init__(self, username="mumble-bot", password=""):
        self.username = username
        self.password = password
        self._channels = {}
        self._users = {}
        self.session_id = None
        self._message_handlers = {MessageType.VERSION: self._message_handler_version,
                                  MessageType.UDPTUNNEL: self._message_handler_udp_tunnel,
                                  MessageType.PING: self._message_handler_ping,
                                  MessageType.REJECT: self._message_handler_reject,
                                  MessageType.SERVERSYNC: self._message_handler_server_sync,
                                  MessageType.CHANNELREMOVE: self._message_handler_channel_remove,
                                  MessageType.CHANNELSTATE: self._message_handler_channel_state,
                                  MessageType.USERREMOVE: self._message_handler_user_remove,
                                  MessageType.USERSTATE: self._message_handler_user_state,
                                  MessageType.BANLIST: self._message_handler_ban_list,
                                  MessageType.TEXTMESSAGE: self._message_handler_text_message,
                                  MessageType.PERMISSIONDENIED: self._message_handler_permission_denied,
                                  MessageType.ACL: self._message_handler_acl,
                                  MessageType.QUERYUSERS: self._message_handler_query_users,
                                  MessageType.CRYPTSETUP: self._message_handler_crypt_setup,
                                  MessageType.USERLIST: self._message_handler_user_list,
                                  MessageType.PERMISSIONQUERY: self._message_handler_permission_query,
                                  MessageType.CODECVERSION: self._message_handler_codec_version,
                                  MessageType.USERSTATS: self._message_handler_user_stats,
                                  MessageType.SERVERCONFIG: self._message_handler_server_config,
                                  MessageType.SUGGESTCONFIG: self._message_handler_suggest_config,
                                  }
        self._event_handlers = {}
        for event in EventType:
            self._event_handlers[event] = EventHandler()
        self._address = None
        self._port = None
        self._certfile = None
        self._keyfile = None
        self._keypassword = None
        self._log = None
        self._tcp_connection_thread = None
        self._udp_connection_thread = None
        self._tcp_message_buffer = None
        self._ping_thread = None
        self._event_queue = queue.Queue()
        self._event_handler_thread = Thread(target=self._event_worker)
        self._event_handler_thread.start()
        self._ssl_socket = None
        self._udp_socket = None
        self._audio_enabled = False
        self._preferred_audio_codec = AudioType.OPUS
        self._audio_decoders = None
        self._audio_encoders = None
        self._audio_target = 0
        self._audio_sequence_number = 0
        self._connection_state = ConnectionState.DISCONNECTED
        self._max_bandwidth = None
        self._crypto = None
        self._encryption_key = None
        self._client_nonce = None
        self._server_nonce = None
        self._last_ping_time = 0
        self._max_message_length = None
        self._max_image_message_length = None
        self._server_allow_html = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.disconnect()

    # message type 0
    def _message_handler_version(self, payload):
        message = mumble_pb2.Version()
        message.ParseFromString(payload)
        server_version = struct.unpack('>HBB', struct.pack('>I', message.version))
        self._log.debug('Server version: {}.{}.{}'.format(*server_version))
        if PROTOCOL_VERSION[0] == server_version[0] and PROTOCOL_VERSION[1] >= server_version[1]:
            self._log.debug('Sending our version: {}.{}.{}...'.format(*PROTOCOL_VERSION))
            version_response = mumble_pb2.Version()
            version_response.version = struct.unpack('>I', struct.pack('>HBB', *PROTOCOL_VERSION))[0]
            version_response.release = RELEASE_STRING
            version_response.os = OS_STRING
            version_response.os_version = OS_VERSION_STRING
            self._send_payload(MessageType.VERSION, version_response)
            self._log.debug('Sending authentication message...')
            authenticate_response = mumble_pb2.Authenticate()
            authenticate_response.username = self.username
            authenticate_response.password = self.password
            # authenticate_response.tokens = ""
            authenticate_response.celt_versions.extend([-2147483637])
            authenticate_response.opus = True
            self._send_payload(MessageType.AUTHENTICATE, authenticate_response)
        else:
            self._log.error('Version mismatch! Our version is {}.{}.{}. Killing connection...'.format(*PROTOCOL_VERSION))

    # message type 1 -- UDPTunnel
    def _message_handler_udp_tunnel(self, payload):
        self._handle_audio(payload)

    # message type 2 -- Authenticate
    # not sent by server, no handler needed

    # message type 3
    def _message_handler_ping(self, payload):
        message = mumble_pb2.Ping()
        message.ParseFromString(payload)
        self._log.debug('Pong: {}'.format(message))

    # message type 4
    def _message_handler_reject(self, payload):
        message = mumble_pb2.Reject()
        message.ParseFromString(payload)
        rejection_type = message.RejectType.Name(message.type)
        reason = message.reason
        self._log.error(f'Server rejected connection. Type: {rejection_type}. Reason: {reason}')
        self._connection_state = ConnectionState.DISCONNECTED

    # message type 5
    def _message_handler_server_sync(self, payload):
        message = mumble_pb2.ServerSync()
        message.ParseFromString(payload)
        self.session_id = message.session
        self._max_bandwidth = message.max_bandwidth
        self._log.info('Connected to server')
        self._udp_connection_thread = Thread(target=self._start_udp_connection)
        self._udp_connection_thread.start()
        self._event_queue.put(Event(self, EventType.CONNECTED, message))

    # message type 6
    def _message_handler_channel_remove(self, payload):
        message = mumble_pb2.ChannelRemove()
        message.ParseFromString(payload)
        try:
            channel_name = self.get_channel(message.channel_id).name
            self._log.debug(f'Removing channel ID {message.channel_id} ({channel_name})')
            del(self._channels[message.channel_id])
            self._event_queue.put(Event(self, EventType.CHANNEL_REMOVED, message))
        except KeyError:
            pass

    # message type 7
    def _message_handler_channel_state(self, payload):
        message = mumble_pb2.ChannelState()
        message.ParseFromString(payload)
        try:
            channel = self.get_channel(message.channel_id)
            channel.update(message)
            self._event_queue.put(Event(self, EventType.CHANNEL_UPDATED, message))  # TODO: be more specific, what changed?
        except KeyError:
            self._channels[message.channel_id] = Channel(self, message)
            self._event_queue.put(Event(self, EventType.CHANNEL_ADDED, message))

    # message type 8
    def _message_handler_user_remove(self, payload):
        """
        Murmur sends two UserRemove messages when someone is kicked or banned.
        The first one contains the session, actor, reason, and ban fields.
        The second message contains only the session ID of the victim.
        However, when someone simply leaves the server, only the second message is sent.
        """
        message = mumble_pb2.UserRemove()
        message.ParseFromString(payload)
        if message.session == self.session_id:
            self._connection_state = ConnectionState.DISCONNECTED
        try:
            session_username = self.get_user(message.session).name
        except KeyError:
            return
        if message.HasField('actor'):
            actor_username = self.get_user(message.actor).name
            if message.ban:
                action = "banned"
                self._event_queue.put(Event(self, EventType.USER_BANNED, message))
            else:
                action = "kicked"
                self._event_queue.put(Event(self, EventType.USER_KICKED, message))
            log_message = f"{actor_username} {action} {session_username} (Reason: {message.reason})"
        else:
            del(self._users[message.session])
            log_message = f"{session_username} left the server"
            self._event_queue.put(Event(self, EventType.USER_DISCONNECTED, message))
        self._log.debug(log_message)

    # message type 9
    def _message_handler_user_state(self, payload):
        message = mumble_pb2.UserState()
        message.ParseFromString(payload)
        try:
            user = self.get_user(message.session)
            message_fields = message.ListFields()
            events_to_fire = []
            fields_changed = [field.name for field, value in message_fields]
            for field_changed in fields_changed:
                if field_changed == 'comment':
                    events_to_fire.append(EventType.USER_COMMENT_UPDATED)
                elif field_changed == 'texture':
                    events_to_fire.append(EventType.USER_TEXTURE_UPDATED)
                elif field_changed == 'user_id':
                    if message.user_id == 0xFFFFFFFF:
                        # murmur sends back the maximum value of a uint32 to signify that a user was unregistered
                        events_to_fire.append(EventType.USER_UNREGISTERED)
                    else:
                        events_to_fire.append(EventType.USER_REGISTERED)
                elif field_changed == 'self_mute':
                    if user.self_mute == message.self_mute:
                        # they didn't change this field.
                        # Murmur oddly sends both the self_mute and self_deaf fields, even if only one changed.
                        # Murmur does not send both fields if an admin mutes or deafens a user on the server.
                        continue
                    elif message.self_mute:
                        events_to_fire.append(EventType.USER_SELF_MUTED)
                    else:
                        events_to_fire.append(EventType.USER_SELF_UNMUTED)
                elif field_changed == 'self_deaf':
                    if user.self_deaf == message.self_deaf:
                        continue
                    elif message.self_deaf:
                        events_to_fire.append(EventType.USER_SELF_DEAFENED)
                    else:
                        events_to_fire.append(EventType.USER_SELF_UNDEAFENED)
                elif field_changed == 'mute':
                    if message.mute:
                        events_to_fire.append(EventType.USER_MUTED)
                    else:
                        events_to_fire.append(EventType.USER_UNMUTED)
                elif field_changed == 'deaf':
                    if message.deaf:
                        events_to_fire.append(EventType.USER_DEAFENED)
                    else:
                        events_to_fire.append(EventType.USER_UNDEAFENED)
                elif field_changed == 'recording':
                    if message.recording:
                        events_to_fire.append(EventType.USER_RECORDING)
                    else:
                        events_to_fire.append(EventType.USER_STOPPED_RECORDING)
            user.update(message)
            for event_type in events_to_fire:
                self._event_queue.put(Event(self, event_type, message))
        except KeyError:
            self._users[message.session] = User(self, message)
            self._event_queue.put(Event(self, EventType.USER_CONNECTED, message))

    # message type 10
    def _message_handler_ban_list(self, payload):
        message = mumble_pb2.BanList()
        message.ParseFromString(payload)
        self._log.debug("Received message type 10")
        self._log.debug(message)
        self._event_queue.put(Event(self, EventType.BANLIST_MODIFIED, message))

    # message type 11
    def _message_handler_text_message(self, payload):
        message = mumble_pb2.TextMessage()
        message.ParseFromString(payload)
        sender_id = message.actor
        recipient_id = message.session
        channel_id = message.channel_id
        tree_id = message.tree_id
        message_body = message.message
        self._log.debug(f'Text message from {sender_id} to {recipient_id} (channel: {channel_id}, tree_id: {tree_id}): {message_body}')
        self._event_queue.put(Event(self, EventType.MESSAGE_RECEIVED, message))

    # message type 12
    def _message_handler_permission_denied(self, payload):
        message = mumble_pb2.PermissionDenied()
        message.ParseFromString(payload)
        deny_type = message.DenyType.Name(message.type)
        reason = message.reason
        self._log.debug(f'Permission denied. Type: {deny_type}. Reason: {reason}')

    # message type 13
    def _message_handler_acl(self, payload):
        message = mumble_pb2.ACL()
        message.ParseFromString(payload)
        self._log.debug("Received message type 13")
        self._log.debug(message)

    # message type 14
    def _message_handler_query_users(self, payload):
        message = mumble_pb2.QueryUsers()
        message.ParseFromString(payload)
        self._log.debug("Received message type 14")
        self._log.debug(message)

    # message type 15
    def _message_handler_crypt_setup(self, payload):
        message = mumble_pb2.CryptSetup()
        message.ParseFromString(payload)
        if message.HasField('key'):
            self._encryption_key = message.key
        if message.HasField('client_nonce'):
            self._client_nonce = message.client_nonce
        if message.HasField('server_nonce'):
            self._server_nonce = message.server_nonce
        self._crypto = MumbleCrypto(self._encryption_key, self._client_nonce, self._server_nonce)

    # message type 16 -- ContextActionModify
    # not sent by server, no handler needed
    # TODO: handle sending these to the server, what does this do?

    # message type 17 -- ContextAction
    # not sent by server, no handler needed
    # TODO: handle sending these to the server, what does this do?

    # message type 18
    def _message_handler_user_list(self, payload):
        message = mumble_pb2.UserList()
        message.ParseFromString(payload)
        self.registered_users = {user.user_id: user.name for user in message.users}
        self._event_queue.put(Event(self, EventType.REGISTERED_USER_LIST_RECEIVED, message))

    # message type 19 -- VoiceTarget
    # not sent by server, no handler needed

    # message type 20
    def _message_handler_permission_query(self, payload):
        message = mumble_pb2.PermissionQuery()
        message.ParseFromString(payload)
        if message.flush:
            for channel in self._channels.values():
                channel.permissions = None
        self.get_channel(message.channel_id).permissions = message.permissions
        self._event_queue.put(Event(self, EventType.CHANNEL_PERMISSIONS_UPDATED, message))

    # message type 21
    def _message_handler_codec_version(self, payload):
        message = mumble_pb2.CodecVersion()
        message.ParseFromString(payload)
        if not message.opus:
            self._audio_enabled = False
            self._log.warning("Server does not support Opus, disabling audio")
            self._event_queue.put(Event(self, EventType.AUDIO_DISABLED, message))

    # message type 22
    def _message_handler_user_stats(self, payload):
        message = mumble_pb2.UserStats()
        message.ParseFromString(payload)
        user = self.get_user(message.session)
        user.update(message, prefix='stats')
        if message.HasField('address'):
            # murmur sends IP addresses encoded in 16 bytes.
            # IPv4 addresses fill most of the array with zeroes, followed by 255, 255, #, #, #, #
            # (where #'s are the four octets of the IPv4 address, in )
            ip = struct.unpack('16B', message.address)
            if ip[0:12] == (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255):
                ip = '.'.join(map(str, ip[12:]))
            else:
                ip = IPv6Address(bytes(ip)).compressed
            user.stats.address = ip
        self._event_queue.put(Event(self, EventType.USER_STATS_UPDATED, message))

    # message type 23 -- RequestBlob
    # not sent by server, no handler needed

    # message type 24
    def _message_handler_server_config(self, payload):
        message = mumble_pb2.ServerConfig()
        message.ParseFromString(payload)
        self._max_message_length = message.message_length
        self._max_image_message_length = message.image_message_length
        self._server_allow_html = message.allow_html

    # message type 25
    def _message_handler_suggest_config(self, payload):
        # nothing important in this message type, maybe implement in the future
        pass

    def _event_worker(self):
        while True:
            event = self._event_queue.get()
            if event is None:
                break
            self._fire_event(event)
            self._event_queue.task_done()

    def _handle_audio(self, payload):
        """
        Parses and handles incoming audio transmissions.

        Args:
          payload(bytes): an unencrypted audio packet

        Returns:
            None
        """
        header = struct.unpack('!B', payload[:1])[0]
        audio_type = (header & 0b11100000) >> 5
        target = header & 0b00011111
        if target != 0:
            # TODO: handle this
            pass  # this is not normal talking, they used an audio target or this is server loopback audio
        payload = payload[1:]
        varint_reader = VarInt(payload)
        if audio_type == AudioType.PING:
            ping_sent_time = varint_reader.read_next()
            self.last_udp_ping_received = time()
            self._log.debug(f"UDP ping from {ping_sent_time}, response received at {self.last_udp_ping_received}")
            return
        elif audio_type == AudioType.OPUS:
            session_id = varint_reader.read_next()  # the user that sent the voice transmission
            sequence_number = varint_reader.read_next()
            size = varint_reader.read_next()
            if size & 0x2000:
                terminate = True
            else:
                terminate = False
            size = size & 0x1fff
            voice_frame = varint_reader.get_current_data()[:size]  # anything left after size is position data
            # TODO: Handle position data
            pcm = self._audio_decoders[audio_type].decode(voice_frame, frame_size=5760)  # 48000 / 100 * 12
            user = self.get_user(session_id)
            user.audio_buffer += pcm
            user.audio_buffer_dict[sequence_number] = pcm
            if terminate:
                user.audio_log.append((time(), user.audio_buffer_dict))
                user.audio_buffer = b''
                user.audio_buffer_dict = {}
                # TODO: need more info in audio-related events
                self._event_queue.put(Event(self, EventType.AUDIO_TRANSMISSION_RECEIVED))

    def _encrypt(self, data):
        """
        Encrypts the data with OCB-AES128, using the key and nonce provided by the server.

        Args:
          data(bytes): the data to encrypt

        Returns:
            bytes: the encrypted data
        """
        tag, ciphertext = self._crypto.encrypt(data)
        ciphertext = self._crypto.client_nonce[0:1] + tag[0:3] + ciphertext
        return bytes(ciphertext)

    def _decrypt(self, data):
        """
        Decrypts the data with OCB-AES128, using the key and nonce provided by the server.

        Args:
          data(bytes): encrypted data

        Returns:
            bytes: the decrypted data
        """
        nonce_byte = data[0:1]
        tag = data[1:4]
        data = data[4:]
        decryption_tag, plaintext = self._crypto.decrypt(data, nonce_byte)
        assert tag == decryption_tag[0:3], f"Decryption tag does not match, decryption failed"
        return plaintext

    def _start_udp_connection(self):
        """
        The process for establishing the UDP connection is:
        1. Client receives the CryptSetup message from the server, containing the encryption parameters
        2. Client sends an encrypted UDP ping packet (header + varint-encoded timestamp)
        3. Server echoes back the same data
        4. Voice data can now be sent and received via UDP

        Returns:
            None
        """
        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ping(udp=True)
        self._udp_socket.settimeout(6)
        try:
            response, sender = self._udp_socket.recvfrom(2048)
        except socket.timeout:
            self._udp_socket.close()
            self._log.warning("Timed out waiting for UDP ping response from server. Using TCP for audio traffic.")
            self._connection_state = ConnectionState.CONNECTED_NO_UDP
            return
        self._decrypt(response)  # will raise exception is something goes wrong
        self._udp_socket.settimeout(None)
        self._connection_state = ConnectionState.CONNECTED_UDP
        self._log.debug("Using UDP for audio traffic")
        self._event_queue.put(Event(self, EventType.UDP_CONNECTED))
        while self._connection_state == ConnectionState.CONNECTED_UDP:
            inputs, outputs, exceptions = select.select([self._udp_socket], [], [])
            for input_socket in inputs:
                try:
                    udp_message_buffer, sender = input_socket.recvfrom(2048)
                except OSError:
                    self._log.debug("UDP socket died, switching to TCP")
                    self._connection_state = ConnectionState.CONNECTED_NO_UDP
                    continue
                if len(udp_message_buffer) == 0:  # connection closed by server
                    self._log.debug("UDP socket returned 0 bytes, closing connection and switching to TCP")
                    self._connection_state = ConnectionState.CONNECTED_NO_UDP
                    continue
                try:
                    decrypted_udp_message = self._decrypt(udp_message_buffer)
                    self._handle_audio(decrypted_udp_message)
                except Exception:
                    self._log.error(f"Failed to handle UDP message. Exception: {traceback.format_exc()}")
        else:
            self._event_queue.put(Event(self, EventType.UDP_DISCONNECTED))

    def _send_packet_udp(self, data):
        self._udp_socket.sendto(self._encrypt(data), (self._address, self._port))

    def _start_tcp_connection(self):
        self._tcp_message_buffer = b""
        while self._connection_state != ConnectionState.DISCONNECTED:
            inputs, outputs, exceptions = select.select([self._ssl_socket], [], [])
            for input_socket in inputs:
                try:
                    self._tcp_message_buffer += input_socket.recv(4096)
                except OSError:
                    self._log.debug("TCP socket died")
                    self._connection_state = ConnectionState.DISCONNECTED
                    continue
                if len(self._tcp_message_buffer) == 0:  # connection closed by server
                    self._log.debug("TCP socket returned 0 bytes, closing connection")
                    self._connection_state = ConnectionState.DISCONNECTED
                    continue

                while len(self._tcp_message_buffer) >= 6:  # message header present
                    message_type = int.from_bytes(self._tcp_message_buffer[0:2], byteorder='big')
                    message_length = int.from_bytes(self._tcp_message_buffer[2:6], byteorder='big')
                    if len(self._tcp_message_buffer) >= 6 + message_length:
                        message_payload = self._tcp_message_buffer[6:6 + message_length]
                    else:  # need to read more, buffer only contains partial packet
                        self._tcp_message_buffer += input_socket.recv(4096)
                        continue
                    self._tcp_message_buffer = self._tcp_message_buffer[6 + message_length:]

                    try:
                        self._message_handlers[message_type](message_payload)
                    except Exception as e:
                        self._log.warning(f'Caught exception ({e}) while handling message type {message_type}, \n'
                                          f'message = {message_payload} \n',
                                          f'exception = {traceback.format_exc()}')
        else:
            self._event_queue.put(Event(self, EventType.DISCONNECTED))

    def _fire_event(self, event):
        self._log.debug(f"Firing event type {event}")
        self._event_handlers[event.type](self, event)

    def _ping_worker(self):
        self._last_ping_time = 0
        while self.is_alive():
            sleep(1)
            if (int(time()) - self._last_ping_time) >= PING_INTERVAL:
                self.ping()
                if self._connection_state == ConnectionState.CONNECTED_UDP:
                    self.ping(udp=True)

    def _send_payload(self, message_type, payload):
        packet = struct.pack('!HL', message_type, payload.ByteSize()) + payload.SerializeToString()
        try:
            self._ssl_socket.send(packet)
        except OSError:
            return False

    def add_event_handler(self, event_type, function_handle):
        """
        Adds the function as a handler for the specified event type.
        When an event is fired, any functions added as handlers for that event type will be run with two arguments,
        the Mumpy instance that the event originated from (in case you have multiple instances running), as well as
        the protobuf message that caused the event to be fired.

        Example::

            def kick_handler_function(mumpy_instance, raw_message):
                kicked_user = mumpy_instance.get_user_by_id(raw_message.session)
                kicker_session_id = raw_message.actor
                reason = raw_message.reason

            bot.add_event_handler(EventType.USER_KICKED, kick_handler_function)

        Args:
            event_type(str): an event from the :class:`~mumpy.constants.EventType` enum
            function_handle(function): the function to run when the specified event is fired

        Returns:
            None
        """
        self._event_handlers[event_type].append(function_handle)

    def connect(self, address, port=64738, certfile=None, keyfile=None, keypassword=None, timeout=30):
        """
        Starts the connection thread that connects to address:port.
        Optionally uses an SSL certificate in PEM format to identify the client.

        Args:
            address(str): string containing either an IP address, FQDN, hostname, etc.
            port(int): the TCP port that the server is running on (Default value = 64738)
            certfile(str, optional): the path to the SSL certificate file in PEM format (Default value = None)
            keyfile(str, optional): the path to the certificate's key file (Default value = None)
            keypassword(str, optional): the secret key used to unlock the key file (Default value = None)
            timeout(int): timeout for initializing a connection

        Returns:
            None
        """
        self._address = address
        self._port = port
        self._certfile = certfile
        self._keyfile = keyfile
        self._keypassword = keypassword
        self._log = logging.getLogger(f'{self.username}@{self._address}:{self._port}')
        try:
            import opuslib
            self._audio_decoders = {AudioType.OPUS: opuslib.Decoder(48000, 1)}
            self._audio_encoders = {AudioType.OPUS: opuslib.Encoder(48000, 1, opuslib.APPLICATION_AUDIO)}
            self._audio_enabled = True
            self._event_queue.put(Event(self, EventType.AUDIO_ENABLED))
        except Exception:
            self._log.warning('Failed to initialize Opus audio codec. Disabling audio')
            self._event_queue.put(Event(self, EventType.AUDIO_DISABLED))
        self._connection_state = ConnectionState.CONNECTING
        self._log.debug(f"Connecting to {self._address}:{self._port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self._address, self._port))
        ssl_context = SSLContext(PROTOCOL_TLS)
        if self._certfile is not None:
            ssl_context.load_cert_chain(self._certfile, keyfile=self._keyfile, password=self._keypassword)
        self._ssl_socket = ssl_context.wrap_socket(sock)
        self._ping_thread = Thread(target=self._ping_worker)
        self._ping_thread.start()
        self._tcp_connection_thread = Thread(target=self._start_tcp_connection)
        self._tcp_connection_thread.start()
        # do not return from this method until the connection is fully established and usable, or it fails
        connection_timer = 0
        while self._connection_state not in (ConnectionState.CONNECTED_UDP, ConnectionState.CONNECTED_NO_UDP,
                                             ConnectionState.DISCONNECTED):
            sleep(0.1)
            connection_timer += 0.1
            if connection_timer > timeout:
                self._connection_state = ConnectionState.DISCONNECTED
                raise TimeoutError(f"Failed to connect to {self._address}:{self._port} within {timeout} seconds")

    def disconnect(self):
        """
        Closes the connection to the server.

        Returns:
            None
        """
        if self._connection_state != ConnectionState.DISCONNECTED:
            try:
                self._ssl_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                self._ssl_socket.close()
            if self._udp_socket is not None:
                try:
                    self._udp_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                finally:
                    self._udp_socket.close()
        self._connection_state = ConnectionState.DISCONNECTED

    @property
    def user(self):
        """
        Returns:
            User: the bot's User
        """
        return self.get_user(self.session_id)

    def get_users(self):
        """
        Returns:
            dict: a dictionary of :class:`.User` objects and IDs in the form ``{<user_id>: User(), ...}``
        """
        return self._users

    def get_channels(self):
        """
        Returns:
            dict: a dictionary of :class:`.Channel` objects and IDs in the form ``{<channel_id>: Channel(), ...}``
        """
        return self._channels

    @property
    def channel_id(self):
        """
        Returns:
            int: the ID of the channel the bot is currently in
        """
        return self.user.channel_id

    @property
    def channel(self):
        """
        Returns:
            Channel: the Channel the bot is currently in
        """
        return self.get_channel(self.channel_id)

    def _get_channel_by_id(self, channel_id):
        """
        Args:
            channel_id(int): the ID of the channel

        Returns:
            Channel: the Channel identified by channel_id
        """
        return self._channels[channel_id]

    def _get_channel_by_name(self, name):
        """
        Args:
            name(str): the name of the channel

        Returns:
            Channel: the Channel identified by name
        """
        for channel_id, channel in self._channels.items():
            if channel.name == name:
                return channel
        raise IndexError(f"Channel with the specified name does not exist: {name}")

    def get_channel(self, identifier):
        """
        Args:
            identifier(int, str): the channel's ID or name

        Returns:
            Channel:
        """
        if isinstance(identifier, int):
            return self._get_channel_by_id(identifier)
        elif isinstance(identifier, str):
            return self._get_channel_by_name(identifier)
        else:
            raise TypeError("identifier must be int or str.")

    def _get_user_by_id(self, session_id):
        """
        Args:
            session_id(int): the session ID of the user

        Returns:
            User: the User identified by session_id
        """
        return self._users[session_id]

    def _get_user_by_name(self, name):
        """
        Args:
            name(str): the name of the user

        Returns:
            User: the User identified by name
        """
        for session_id, user in self._users.items():
            if user.name == name:
                return user
        raise IndexError(f"User with the specified name does not exist: {name}")

    def get_user(self, identifier):
        """
        Args:
            identifier(int, str): the user's ID or name

        Returns:
            User:
        """
        if isinstance(identifier, int):
            return self._get_user_by_id(identifier)
        elif isinstance(identifier, str):
            return self._get_user_by_name(identifier)
        else:
            raise TypeError("identifier must be int or str.")

    def kick_user(self, user, reason="", ban=False):
        """
        Kicks a User. Bans the User if ban is True.

        Args:
            user(User): the target User
            reason(str): the reason for this action (Default value = "")
            ban(bool): whether or not the user should be banned as well (Default value = False)

        Returns:
            None
        """
        kick_payload = mumble_pb2.UserRemove()
        kick_payload.session = user.session_id
        kick_payload.reason = reason
        kick_payload.ban = ban
        self._send_payload(MessageType.USERREMOVE, kick_payload)

    def kick_user_by_name(self, name, reason="", ban=False):
        """
        Kicks a user identified by name. Bans the user if ban is True.

        Args:
            name(str): the target User's name
            reason(str): the reason for this action (Default value = "")
            ban(bool): whether or not the user should be banned as well (Default value = False)

        Returns:
            None
        """
        user = self.get_user(name)
        self.kick_user(user, reason=reason, ban=ban)

    def clear_all_audio_logs(self):
        """
        Clears every user's audio log, removing all received audio transmissions from memory.
        """
        for session_id, user in self.get_users().items():
            user.audio_log = []

    @staticmethod
    def _export_to_wav(pcm, filename):
        """
        Converts the raw PCM audio data to WAV and saves it to a file.

        Args:
            pcm(bytes): raw PCM audio data
            filename(str): the path to the file where the audio data should be written

        Returns:
            None
        """
        f = wave.open(filename, 'wb')
        f.setnchannels(1)  # mono
        f.setsampwidth(2)  # 16-bit
        f.setframerate(48000)  # 48KHz
        f.writeframes(pcm)
        f.close()

    def export_audio_logs_to_wav(self, folder='./'):
        """
        Converts all audio logs from all users to WAV and saves them to separate files.
        Clears all audio logs once the audio has been saved.

        Args:
            folder(str): the output directory (Default value = './')

        Returns:
            None
        """
        for session_id, user in self.get_users().items():
            counter = 1
            base_filename = folder + user.name + '_'
            for timestamp, pcm_dict in user.audio_log:
                filename = f"{base_filename}{int(timestamp)}.wav"
                combined_pcm = bytes()
                for sequence_number in sorted(pcm_dict):
                    combined_pcm += pcm_dict[sequence_number]
                self._export_to_wav(combined_pcm, filename)
                counter += 1
            user.audio_log = []

    def _send_audio_packet_tcp(self, udp_packet):
        """
        Sends a UDP audio packet to the server through the TCP socket.

        Args:
            udp_packet(bytes): an unencrypted payload of audio data, formatted according to the Mumble protocol

        Returns:
            None
        """
        packet = struct.pack('!HL', MessageType.UDPTUNNEL, len(udp_packet)) + udp_packet
        self._ssl_socket.send(packet)

    def send_audio(self, pcm, sample_rate=48000, sample_width=2):
        """
        Encodes raw PCM data using the preferred audio codec and transmits it to the server.

        Args:
            pcm(bytes): the raw PCM data
            sample_rate(int): the sample rate of the PCM data (Default value = 48000)
            sample_width(int): the sample width of the PCM data (AKA the bit depth, but in bytes) (Default value = 2)

        Returns:
            None
        """
        frame_size = int(sample_rate / 100)
        frame_width = sample_width
        encoded_audio = []
        while len(pcm) > 0:
            to_encode = pcm[:frame_size * frame_width]
            pcm = pcm[frame_size * frame_width:]
            encoded_audio.append(self._audio_encoders[self._preferred_audio_codec].encode(to_encode, frame_size))
        header = struct.pack('!B', self._preferred_audio_codec << 5 | self._audio_target)
        for frame in encoded_audio[:-1]:
            sequence_number = VarInt(self._audio_sequence_number).encode()
            # TODO: positional info. struct.pack('!fff', 1.0, 2.0, 3.0)
            payload = VarInt(len(frame)).encode() + frame
            udp_packet = header + sequence_number + payload
            self._send_audio_packet_tcp(udp_packet)
            self._audio_sequence_number += 1
        # set the terminator bit for the last payload
        frame = encoded_audio[-1]
        sequence_number = VarInt(self._audio_sequence_number).encode()
        payload = VarInt(len(frame) | 0x2000).encode() + frame
        udp_packet = header + sequence_number + payload
        if self._connection_state == ConnectionState.CONNECTED_UDP:
            self._send_packet_udp(udp_packet)
        else:
            self._send_audio_packet_tcp(udp_packet)
        self._audio_sequence_number += 1
        self._event_queue.put(Event(self, EventType.AUDIO_TRANSMISSION_SENT))

    def play_wav(self, filename):
        """
        Reads a WAV file and then sends it as an audio transmission.

        Args:
            filename(str): the path to the WAV file

        Returns:
            None
        """
        f = wave.open(filename, 'rb')
        total_frames = f.getnframes()
        samples = f.readframes(total_frames)
        freq = f.getframerate()
        width = f.getsampwidth()
        f.close()
        self.send_audio(samples, freq, width)

    def text_message(self, message, channels=(), users=()):
        """
        Sends a text message to each Channel in the list channels, and to each User in the list users.
        If no channels or users are specified, sends the message to the bot's current channel.

        Args:
            message(str): the text message
            channels(iterable): a list of channels to send the message to (Default value = ())
            users(iterable): a list of users to send the message to (Default value = ())

        Returns:
            None
        """
        message_payload = mumble_pb2.TextMessage()
        message_payload.message = message
        if len(channels) == 0 and len(users) == 0:
            message_payload.channel_id.append(self.channel_id)
        if channels:
            message_payload.channel_id.extend([channel.id for channel in channels])
        if users:
            message_payload.session.extend([user.session_id for user in users])
        self._send_payload(MessageType.TEXTMESSAGE, message_payload)
        self._event_queue.put(Event(self, EventType.MESSAGE_SENT, message_payload))

    def ping(self, udp=False):
        """
        Sends a Ping packet to the server, as specified by the Mumble protocol.

        Args:
            udp(boolean): if True, sends a UDP ping. Otherwise, sends a TCP ping. (Default value = False)

        Returns:
            None
        """
        if udp:
            udp_ping_packet = b'\x20' + VarInt(int(time())).encode()
            self._send_packet_udp(udp_ping_packet)
        else:
            ping_payload = mumble_pb2.Ping()
            ping_payload.timestamp = int(time())
            self._send_payload(MessageType.PING, ping_payload)
            self._last_ping_time = ping_payload.timestamp

    def is_alive(self):
        """
        Returns:
            bool: True if bot is connected to the server
        """
        return self._connection_state != ConnectionState.DISCONNECTED

    def is_udp_alive(self):
        """
        Returns:
            bool: True if the bot has an active UDP connection to the server
        """
        return self._connection_state == ConnectionState.CONNECTED_UDP

    def update_user_stats(self, user):
        """
        Queries the server for a User's stats.

        Args:
            user(User): the User to retrieve stats for

        Returns:
            None

        Events:
            - :obj:`.USER_STATS_UPDATED`
        """
        message_payload = mumble_pb2.UserStats()
        message_payload.session = user.session_id
        self._send_payload(MessageType.USERSTATS, message_payload)

    def request_blob(self, user_textures=(), user_comments=(), channel_descriptions=()):
        """
        Queries the server for the full contents of a User's texture or comment, or a Channel's description.

        Args:
            user_textures(iterable): a list of Users to retrieve textures for (Default value = ())
            user_comments(iterable): a list of Users to retrieve comments for (Default value = ())
            channel_descriptions(iterable): a list of Channels to retrieve descriptions for (Default value = ())

        Returns:
            None

        Events:
            - :obj:`.USER_COMMENT_UPDATED`
            - :obj:`.USER_TEXTURE_UPDATED`
            - :obj:`.CHANNEL_UPDATED`
        """
        message_payload = mumble_pb2.RequestBlob()
        message_payload.session_texture.extend(user_textures)
        message_payload.session_comment.extend(user_comments)
        message_payload.channel_description.extend(channel_descriptions)
        self._send_payload(MessageType.REQUESTBLOB, message_payload)

    def move_user_to_channel(self, user, channel):
        """
        Moves the User to the specified Channel.

        Args:
            user(User): the User to move
            channel(Channel): the channel to move the User to

        Returns:
            None
        """
        message_payload = mumble_pb2.UserState()
        message_payload.session = user.session_id
        message_payload.channel_id = channel.id
        self._send_payload(MessageType.USERSTATE, message_payload)

    def join_channel(self, channel):
        """
        Moves the Mumpy instance to the specified Channel.

        Args:
            channel(Channel): the channel to move to

        Returns:
            None
        """
        self.move_user_to_channel(self.user, channel)

    def register_user(self, user):
        """
        Registers a User on the server.

        Args:
            user(User): the User to register

        Returns:
            None
        """
        message_payload = mumble_pb2.UserState()
        message_payload.session = user.session_id
        message_payload.user_id = 0
        self._send_payload(MessageType.USERSTATE, message_payload)

    def unregister_user(self, user):
        """
        Unregisters a User on the server.

        Args:
            user(User): the User to unregister

        Returns:
            None
        """
        message_payload = mumble_pb2.UserList()
        message_payload.users.add()
        try:
            message_payload.users[0].user_id = user.user_id
        except AttributeError:
            # user is already not registered
            return
        self._send_payload(MessageType.USERLIST, message_payload)

    def register_self(self):
        """
        Registers the Mumpy instance on the server.

        Returns:
            None
        """
        self.register_user(self.user)

    def unregister_self(self):
        """
        Unregisters the Mumpy instance on the server.

        Returns:
            None
        """
        self.unregister_user(self.user)

    def mute_user(self, user):
        """
        Mutes a user on the server.

        Args:
            user(User): the user to mute

        Returns:
            None
        """
        message_payload = mumble_pb2.UserState()
        message_payload.session = user.session_id
        message_payload.mute = True
        self._send_payload(MessageType.USERSTATE, message_payload)

    def deafen_user(self, user):
        """
        Deafens a user on the server.

        Args:
            user(User): the user to deafen

        Returns:
            None
        """
        message_payload = mumble_pb2.UserState()
        message_payload.session = user.session_id
        message_payload.deaf = True
        self._send_payload(MessageType.USERSTATE, message_payload)

    def unmute_user(self, user):
        """
        Unmutes a user on the server.

        Args:
            user(User): the user to unmute

        Returns:
            None
        """
        message_payload = mumble_pb2.UserState()
        message_payload.session = user.session_id
        message_payload.mute = False
        self._send_payload(MessageType.USERSTATE, message_payload)

    def undeafen_user(self, user):
        """
        Undeafens a user on the server.

        Args:
            user(User): the user to undeafen

        Returns:
            None
        """
        message_payload = mumble_pb2.UserState()
        message_payload.session = user.session_id
        message_payload.deaf = False
        self._send_payload(MessageType.USERSTATE, message_payload)

    def mute_self(self):
        """
        Mutes the Mumpy instance on the server.

        Returns:
            None
        """
        message_payload = mumble_pb2.UserState()
        message_payload.session = self.session_id
        message_payload.self_mute = True
        self._send_payload(MessageType.USERSTATE, message_payload)

    def deafen_self(self):
        """
        Deafens the Mumpy instance on the server.

        Returns:
            None
        """
        message_payload = mumble_pb2.UserState()
        message_payload.session = self.session_id
        message_payload.self_deaf = True
        self._send_payload(MessageType.USERSTATE, message_payload)

    def unmute_self(self):
        """
        Unmutes the Mumpy instance on the server.

        Returns:
            None
        """
        message_payload = mumble_pb2.UserState()
        message_payload.session = self.session_id
        message_payload.self_mute = False
        message_payload.mute = False
        self._send_payload(MessageType.USERSTATE, message_payload)

    def undeafen_self(self):
        """
        Undeafens the Mumpy instance on the server.

        Returns:
            None
        """
        message_payload = mumble_pb2.UserState()
        message_payload.session = self.session_id
        message_payload.self_deaf = False
        message_payload.deaf = False
        self._send_payload(MessageType.USERSTATE, message_payload)

    def get_channel_permissions(self, channel):
        """
        Retrieves the Mumpy instance's permissions in the specified Channel.
        This function does not return anything. The server's response may fire the following events:
        - CHANNEL_PERMISSIONS_UPDATED

        Args:
            channel(Channel): the Channel to retrieve permissions for

        Returns:
            None
        """
        message_payload = mumble_pb2.PermissionQuery()
        message_payload.channel_id = channel.id
        self._send_payload(MessageType.PERMISSIONQUERY, message_payload)

    def get_registered_users(self):
        """
        Retrieves the list of registered users from the server.
        This function does not return anything. The server's response may fire the following events:
        - REGISTERED_USER_LIST_RECEIVED

        Returns:
            None
        """
        message_payload = mumble_pb2.UserList()
        self._send_payload(MessageType.USERLIST, message_payload)

    def rename_channel(self, channel, new_name):
        """
        Changes a channel's name to new_name.

        Args:
            channel(Channel): the channel to rename
            new_name(str): the new name

        Returns:
            None
        """
        message_payload = mumble_pb2.ChannelState()
        message_payload.channel_id = channel.id
        message_payload.name = new_name
        self._send_payload(MessageType.CHANNELSTATE, message_payload)

    def remove_channel(self, channel):
        """
        Removes a channel.

        Args:
            channel(Channel): the channel to remove

        Returns:
            None
        """
        message_payload = mumble_pb2.ChannelRemove()
        message_payload.channel_id = channel.id
        self._send_payload(MessageType.CHANNELREMOVE, message_payload)

    def configure_voice_target(self, id, users=(), channels=(), acl_groups=(), follow_links=False,
                               children=False):
        message_payload = mumble_pb2.VoiceTarget()
        if len(users) > 0:
            users_target = message_payload.targets.add()
            users_target.session.extend(users)
