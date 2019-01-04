from mumpy.channel import Channel
from mumpy import mumble_pb2
from mumpy.constants import ConnectionState, MessageType, Permission, MumpyEvent, AudioType, PROTOCOL_VERSION, OS_VERSION_STRING,\
    RELEASE_STRING, OS_STRING, PING_INTERVAL
from mumpy.event_handler import EventHandler
from mumpy.mumblecrypto import MumbleCrypto
from mumpy.user import User
from mumpy.varint import VarInt
from ssl import SSLContext, PROTOCOL_TLS
from threading import Thread
from time import time, sleep
import logging
import select
import socket
import struct
import traceback
import wave


class Mumpy:
    def __init__(self, username="mumble-bot", password=""):
        self.username = username
        self.password = password
        self.channels = {}
        self.users = {}
        self.session_id = None
        self.message_handlers = {MessageType.VERSION:       self._message_handler_Version,
                                 MessageType.UDPTUNNEL:     self._message_handler_UDPTunnel,
                                 MessageType.PING:          self._message_handler_Ping,
                                 MessageType.REJECT:        self._message_handler_Reject,
                                 MessageType.SERVERSYNC:    self._message_handler_ServerSync,
                                 MessageType.CHANNELREMOVE: self._message_handler_ChannelRemove,
                                 MessageType.CHANNELSTATE:  self._message_handler_ChannelState,
                                 MessageType.USERREMOVE:    self._message_handler_UserRemove,
                                 MessageType.USERSTATE:     self._message_handler_UserState,
                                 MessageType.BANLIST:       self._message_handler_BanList,
                                 MessageType.TEXTMESSAGE:   self._message_handler_TextMessage,
                                 MessageType.PERMISSIONDENIED: self._message_handler_PermissionDenied,
                                 MessageType.ACL:           self._message_handler_ACL,
                                 MessageType.QUERYUSERS:    self._message_handler_QueryUsers,
                                 MessageType.CRYPTSETUP:    self._message_handler_CryptSetup,
                                 MessageType.USERLIST:      self._message_handler_UserList,
                                 MessageType.PERMISSIONQUERY: self._message_handler_PermissionQuery,
                                 MessageType.CODECVERSION:  self._message_handler_CodecVersion,
                                 MessageType.USERSTATS:     self._message_handler_UserStats,
                                 MessageType.SERVERCONFIG:  self._message_handler_ServerConfig,
                                 MessageType.SUGGESTCONFIG: self._message_handler_SuggestConfig,
                                 }
        self.event_handlers = {}
        for event in MumpyEvent:
            self.event_handlers[event] = EventHandler()
        self.address = None
        self.port = None
        self.certfile = None
        self.keyfile = None
        self.keypassword = None
        self.log = None
        self.tcp_connection_thread = None
        self.udp_connection_thread = None
        self.audio_enabled = False
        self.preferred_audio_codec = AudioType.OPUS
        self.audio_decoders = None
        self.audio_encoders = None
        self.audio_target = 0
        self.audio_sequence_number = 0
        self.connection_state = ConnectionState.DISCONNECTED
        self.max_bandwidth = None
        self.crypto = None
        self.encryption_key = None
        self.client_nonce = None
        self.server_nonce = None
        self.last_ping_time = 0
        self.max_message_length = None
        self.max_image_message_length = None
        self.server_allow_html = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.disconnect()

    # message type 0
    def _message_handler_Version(self, payload):
        message = mumble_pb2.Version()
        message.ParseFromString(payload)
        server_version = struct.unpack('>HBB', struct.pack('>I', message.version))
        self.log.debug('Server version: {}.{}.{}'.format(*server_version))
        if PROTOCOL_VERSION[0] == server_version[0] and PROTOCOL_VERSION[1] >= server_version[1]:
            self.log.debug('Sending our version: {}.{}.{}...'.format(*PROTOCOL_VERSION))
            version_response = mumble_pb2.Version()
            version_response.version = struct.unpack('>I', struct.pack('>HBB', *PROTOCOL_VERSION))[0]
            version_response.release = RELEASE_STRING
            version_response.os = OS_STRING
            version_response.os_version = OS_VERSION_STRING
            self._send_payload(MessageType.VERSION, version_response)
            self.log.debug('Sending authentication message...')
            authenticate_response = mumble_pb2.Authenticate()
            authenticate_response.username = self.username
            authenticate_response.password = self.password
            # authenticate_response.tokens = ""
            authenticate_response.celt_versions.extend([-2147483637])
            authenticate_response.opus = True
            self._send_payload(MessageType.AUTHENTICATE, authenticate_response)
        else:
            self.log.error('Version mismatch! Our version is {}.{}.{}. Killing connection...'.format(*PROTOCOL_VERSION))

    # message type 1 -- UDPTunnel
    def _message_handler_UDPTunnel(self, payload):
        self._handle_audio(payload)

    # message type 2 -- Authenticate
    # not sent by server, no handler needed

    # message type 3
    def _message_handler_Ping(self, payload):
        message = mumble_pb2.Ping()
        message.ParseFromString(payload)
        self.log.debug('Pong: {}'.format(message))

    # message type 4
    def _message_handler_Reject(self, payload):
        message = mumble_pb2.Reject()
        message.ParseFromString(payload)
        rejection_type = message.RejectType.Name(message.type)
        reason = message.reason
        self.log.error(f'Server rejected connection. Type: {rejection_type}. Reason: {reason}')
        self.connection_state = ConnectionState.DISCONNECTED

    # message type 5
    def _message_handler_ServerSync(self, payload):
        message = mumble_pb2.ServerSync()
        message.ParseFromString(payload)
        self.session_id = message.session
        self.max_bandwidth = message.max_bandwidth
        self.log.info('Connected to server')
        self.udp_connection_thread = Thread(target=self._start_udp_connection)
        self.udp_connection_thread.start()
        self._fire_event(MumpyEvent.CONNECTED, message)

    # message type 6
    def _message_handler_ChannelRemove(self, payload):
        message = mumble_pb2.ChannelRemove()
        message.ParseFromString(payload)
        try:
            channel_name = self.get_channel_by_id(message.channel_id).name
            self.log.debug(f'Removing channel ID {message.channel_id} ({channel_name})')
            del(self.channels[message.channel_id])
            self._fire_event(MumpyEvent.CHANNEL_REMOVED, message)
        except Exception:
            pass

    # message type 7
    def _message_handler_ChannelState(self, payload):
        message = mumble_pb2.ChannelState()
        message.ParseFromString(payload)
        try:
            channel = self.get_channel_by_id(message.channel_id)
            channel.update(message)
            self._fire_event(MumpyEvent.CHANNEL_UPDATED, message)  # TODO: be more specific, what changed?
        except Exception:
            self.channels[message.channel_id] = Channel(self, message)
            self._fire_event(MumpyEvent.CHANNEL_ADDED, message)

    # message type 8
    def _message_handler_UserRemove(self, payload):
        """
        Murmur sends two UserRemove messages when someone is kicked or banned.
        The first one contains the session, actor, reason, and ban fields.
        The second message contains only the session ID of the victim.
        However, when someone simply leaves the server, only the second message is sent.
        """
        message = mumble_pb2.UserRemove()
        message.ParseFromString(payload)
        if message.session == self.session_id:
            self.connection_state = ConnectionState.DISCONNECTED
        try:
            session_username = self.get_user_by_id(message.session).name
        except Exception:
            return
        if message.HasField('actor'):
            actor_username = self.get_user_by_id(message.actor).name
            if message.ban:
                action = "banned"
                self._fire_event(MumpyEvent.USER_BANNED, message)
            else:
                action = "kicked"
                self._fire_event(MumpyEvent.USER_KICKED, message)
            log_message = f"{actor_username} {action} {session_username} (Reason: {message.reason})"
        else:
            del(self.users[message.session])
            log_message = f"{session_username} left the server"
            self._fire_event(MumpyEvent.USER_DISCONNECTED, message)
        self.log.debug(log_message)

    # message type 9
    def _message_handler_UserState(self, payload):
        message = mumble_pb2.UserState()
        message.ParseFromString(payload)
        try:
            user = self.get_user_by_id(message.session)
            message_fields = message.ListFields()
            events_to_fire = []
            fields_changed = [field.name for field, value in message_fields]
            for field_changed in fields_changed:
                if field_changed == 'comment':
                    events_to_fire.append(MumpyEvent.USER_COMMENT_UPDATED)
                elif field_changed == 'texture':
                    events_to_fire.append(MumpyEvent.USER_AVATAR_UPDATED)
                elif field_changed == 'user_id':
                    events_to_fire.append(MumpyEvent.USER_REGISTERED)
                elif field_changed == 'self_mute':
                    if user.self_mute == message.self_mute:
                        # they didn't change this field.
                        # Murmur oddly sends both the self_mute and self_deaf fields, even if only one changed.
                        # Murmur does not send both fields if an admin mutes or deafens a user on the server.
                        continue
                    elif message.self_mute:
                        events_to_fire.append(MumpyEvent.USER_SELF_MUTED)
                    else:
                        events_to_fire.append(MumpyEvent.USER_SELF_UNMUTED)
                elif field_changed == 'self_deaf':
                    if user.self_deaf == message.self_deaf:
                        continue
                    elif message.self_deaf:
                        events_to_fire.append(MumpyEvent.USER_SELF_DEAFENED)
                    else:
                        events_to_fire.append(MumpyEvent.USER_SELF_UNDEAFENED)
                elif field_changed == 'mute':
                    if message.mute:
                        events_to_fire.append(MumpyEvent.USER_MUTED)
                    else:
                        events_to_fire.append(MumpyEvent.USER_UNMUTED)
                elif field_changed == 'deaf':
                    if message.deaf:
                        events_to_fire.append(MumpyEvent.USER_DEAFENED)
                    else:
                        events_to_fire.append(MumpyEvent.USER_UNDEAFENED)
                elif field_changed == 'recording':
                    if message.recording:
                        events_to_fire.append(MumpyEvent.USER_RECORDING)
                    else:
                        events_to_fire.append(MumpyEvent.USER_STOPPED_RECORDING)
            user.update(message)
            for event_type in events_to_fire:
                self._fire_event(event_type, message)
        except Exception:
            self.users[message.session] = User(self, message)
            self._fire_event(MumpyEvent.USER_CONNECTED, message)

    # message type 10
    def _message_handler_BanList(self, payload):
        message = mumble_pb2.BanList()
        message.ParseFromString(payload)
        self.log.debug("Received message type 10")
        self.log.debug(message)
        self._fire_event(MumpyEvent.BANLIST_MODIFIED, message)

    # message type 11
    def _message_handler_TextMessage(self, payload):
        message = mumble_pb2.TextMessage()
        message.ParseFromString(payload)
        sender_id = message.actor
        recipient_id = message.session
        channel_id = message.channel_id
        tree_id = message.tree_id
        message_body = message.message
        self.log.debug(f'Text message from {sender_id} to {recipient_id} (channel: {channel_id}, tree_id: {tree_id}): {message_body}')
        self._fire_event(MumpyEvent.MESSAGE_RECEIVED, message)

    # message type 12
    def _message_handler_PermissionDenied(self, payload):
        message = mumble_pb2.PermissionDenied()
        message.ParseFromString(payload)
        type = message.DenyType.Name(message.type)
        reason = message.reason
        self.log.debug(f'Permission denied. Type: {type}. Reason: {reason}')

    # message type 13
    def _message_handler_ACL(self, payload):
        message = mumble_pb2.ACL()
        message.ParseFromString(payload)
        self.log.debug("Received message type 13")
        self.log.debug(message)

    # message type 14
    def _message_handler_QueryUsers(self, payload):
        message = mumble_pb2.QueryUsers()
        message.ParseFromString(payload)
        self.log.debug("Received message type 14")
        self.log.debug(message)

    # message type 15
    def _message_handler_CryptSetup(self, payload):
        message = mumble_pb2.CryptSetup()
        message.ParseFromString(payload)
        if message.HasField('key'):
            self.encryption_key = message.key
        if message.HasField('client_nonce'):
            self.client_nonce = message.client_nonce
        if message.HasField('server_nonce'):
            self.server_nonce = message.server_nonce
        self.crypto = MumbleCrypto(self.encryption_key, self.client_nonce, self.server_nonce)

    # message type 16 -- ContextActionModify
    # not sent by server, no handler needed
    # TODO: handle sending these to the server, what does this do?

    # message type 17 -- ContextAction
    # not sent by server, no handler needed
    # TODO: handle sending these to the server, what does this do?

    # message type 18
    def _message_handler_UserList(self, payload):
        message = mumble_pb2.UserList()
        message.ParseFromString(payload)
        self.registered_users = {user.user_id: user.name for user in message.users}
        self._fire_event(MumpyEvent.REGISTERED_USER_LIST_RECEIVED, message)

    # message type 19 -- VoiceTarget
    # not sent by server, no handler needed
    # TODO: handle sending these to the server

    # message type 20
    def _message_handler_PermissionQuery(self, payload):
        message = mumble_pb2.PermissionQuery()
        message.ParseFromString(payload)
        if message.flush:
            for channel in self.channels.values():
                channel.permissions = None
        self.get_channel_by_id(message.channel_id).permissions = message.permissions
        self._fire_event(MumpyEvent.CHANNEL_PERMISSIONS_UPDATED, message)

    # message type 21
    def _message_handler_CodecVersion(self, payload):
        message = mumble_pb2.CodecVersion()
        message.ParseFromString(payload)
        if not message.opus:
            self.audio_enabled = False
            self.log.warning("Server does not support Opus, disabling audio")
            self._fire_event(MumpyEvent.AUDIO_DISABLED)

    # message type 22
    def _message_handler_UserStats(self, payload):
        # TODO: Send these to the server to give server your stats? Documentation on this feature is unclear
        message = mumble_pb2.UserStats()
        message.ParseFromString(payload)
        user = self.get_user_by_id(message.session)
        user.update(message, prefix='stats')
        self._fire_event(MumpyEvent.USER_STATS_UPDATED, message)

    # message type 23 -- RequestBlob
    # not sent by server, no handler needed

    # message type 24
    def _message_handler_ServerConfig(self, payload):
        message = mumble_pb2.ServerConfig()
        message.ParseFromString(payload)
        self.max_message_length = message.message_length
        self.max_image_message_length = message.image_message_length
        self.server_allow_html = message.allow_html

    # message type 25
    def _message_handler_SuggestConfig(self, payload):
        # nothing important in this message type, maybe implement in the future
        pass

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
        payload = payload[1:]
        varint_reader = VarInt(payload)
        if audio_type == AudioType.PING:
            ping_sent_time = varint_reader.read_next()
            self.last_udp_ping_received = time()
            self.log.debug(f"UDP ping from {ping_sent_time}, response received at {self.last_udp_ping_received}")
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
            pcm = self.audio_decoders[audio_type].decode(voice_frame, frame_size=5760)  # 48000 / 100 * 12
            user = self.get_user_by_id(session_id)
            user.audio_buffer += pcm
            user.audio_buffer_dict[sequence_number] = pcm
            if terminate:
                user.audio_log.append((time(), user.audio_buffer_dict))
                user.audio_buffer = b''
                user.audio_buffer_dict = {}
                self._fire_event(MumpyEvent.AUDIO_TRANSMISSION_RECEIVED, user)

    def _encrypt(self, data):
        """
        Encrypts the data with OCB-AES128, using the key and nonce provided by the server.

        Args:
          data(bytes): the data to encrypt

        Returns:
            bytes: the encrypted data
        """
        tag, ciphertext = self.crypto.encrypt(data)
        ciphertext = self.crypto.client_nonce[0:1] + tag[0:3] + ciphertext
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
        decryption_tag, plaintext = self.crypto.decrypt(data, nonce_byte)
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
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ping(udp=True)
        self.udp_socket.settimeout(6)
        try:
            response, sender = self.udp_socket.recvfrom(2048)
        except socket.timeout:
            self.udp_socket.close()
            self.log.warning("Timed out waiting for UDP ping response from server. Using TCP for audio traffic.")
            return
        response_decrypted = self._decrypt(response)
        self.udp_socket.settimeout(None)
        self.connection_state = ConnectionState.CONNECTED_UDP
        self.log.debug("Using UDP for audio traffic")
        self._fire_event(MumpyEvent.UDP_CONNECTED)
        while self.connection_state == ConnectionState.CONNECTED_UDP:
            inputs, outputs, exceptions = select.select([self.udp_socket], [], [])
            for input_socket in inputs:
                try:
                    udp_message_buffer, sender = input_socket.recvfrom(2048)
                except OSError:
                    self.log.debug("UDP socket died, switching to TCP")
                    self.connection_state = ConnectionState.CONNECTED_NO_UDP
                    continue
                if len(udp_message_buffer) == 0:  # connection closed by server
                    self.log.debug("UDP socket returned 0 bytes, closing connection and switching to TCP")
                    self.connection_state = ConnectionState.CONNECTED_NO_UDP
                    continue
                try:
                    decrypted_udp_message = self._decrypt(udp_message_buffer)
                    self._handle_audio(decrypted_udp_message)
                except Exception:
                    self.log.error(f"Failed to handle UDP message. Exception: {traceback.format_exc()}")
        else:
            self._fire_event(MumpyEvent.UDP_DISCONNECTED)

    def _send_packet_udp(self, data):
        self.udp_socket.sendto(self._encrypt(data), (self.address, self.port))

    def _start_tcp_connection(self):
        self.log.debug(f"Connecting to {self.address}:{self.port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.address, self.port))
        ssl_context = SSLContext(PROTOCOL_TLS)
        if self.certfile is not None:
            ssl_context.load_cert_chain(self.certfile, keyfile=self.keyfile, password=self.keypassword)
        self.ssl_socket = ssl_context.wrap_socket(sock)
        self.ping_thread = Thread(target=self._ping_thread)
        self.ping_thread.start()
        self.tcp_message_buffer = b""
        while self.connection_state != ConnectionState.DISCONNECTED:
            inputs, outputs, exceptions = select.select([self.ssl_socket], [], [])
            for input_socket in inputs:
                try:
                    self.tcp_message_buffer += input_socket.recv(4096)
                except OSError:
                    self.log.debug("TCP socket died")
                    self.connection_state = ConnectionState.DISCONNECTED
                    continue
                if len(self.tcp_message_buffer) == 0:  # connection closed by server
                    self.log.debug("TCP socket returned 0 bytes, closing connection")
                    self.connection_state = ConnectionState.DISCONNECTED
                    continue

                while len(self.tcp_message_buffer) >= 6:  # message header present
                    message_type = int.from_bytes(self.tcp_message_buffer[0:2], byteorder='big')
                    message_length = int.from_bytes(self.tcp_message_buffer[2:6], byteorder='big')
                    if len(self.tcp_message_buffer) >= 6 + message_length:
                        message_payload = self.tcp_message_buffer[6:6+message_length]
                    else:  # need to read more, buffer only contains partial packet
                        self.tcp_message_buffer += input_socket.recv(4096)
                        continue
                    self.tcp_message_buffer = self.tcp_message_buffer[6+message_length:]

                    try:
                        self.message_handlers[message_type](message_payload)
                    except KeyError:
                        self.log.warning(f'Received unhandled message type = {message_type}, '
                                         f'message = {message_payload}')
                    except Exception as e:
                        self.log.warning(f'Caught exception ({e}) while handling message type {message_type}, '
                                         f'message = {message_payload}')
        else:
            self._fire_event(MumpyEvent.DISCONNECTED)

    def _fire_event(self, event_type, message=None):
        self.log.debug(f"Firing event type {event_type}")
        self.event_handlers[event_type](self, message)

    def _ping_thread(self):
        self.last_ping_time = 0
        while self.is_alive():
            sleep(1)
            if (int(time()) - self.last_ping_time) >= PING_INTERVAL:
                self.ping()
                self.ping(udp=True)

    def _send_payload(self, message_type, payload):
        packet = struct.pack('!HL', message_type, payload.ByteSize()) + payload.SerializeToString()
        try:
            self.ssl_socket.send(packet)
        except OSError:
            return False

    def add_event_handler(self, event_type, function_handle):
        """
        Adds the function as a handler for the specified event type.
        When an event is fired, any functions added as handlers for that event type will be run with two arguments,
        the Mumpy instance that the event originated from (in case you have multiple instances running), as well as
        the protobuf message that caused the event to be fired.

        Example:
            def kick_handler_function(mumpy_instance, raw_message):
                kicked_user = mumpy_instance.get_user_by_id(raw_message.session)
                kicker_session_id = raw_message.actor
                reason = raw_message.reason

            bot.add_event_handler(MumpyEvent.USER_KICKED, kick_handler_function)

        Args:
            event_type(MumpyEvent.EVENT_TYPE): an event from the MumpyEvent enum
            function_handle(function): the function to run when the specified event is fired

        Returns:
            None
        """
        self.event_handlers[event_type].append(function_handle)

    def connect(self, address, port=64738, certfile=None, keyfile=None, keypassword=None):
        """
        Starts the connection thread that connects to address:port.
        Optionally uses an SSL certificate in PEM format to identify the client.
        You can generate a self-signed SSL certificate and key file using a command like the following:

        ``# openssl req -newkey rsa:2048 -nodes -keyout mumpy_key.pem -x509 -days 2000 -out mumpy_certificate.pem``

        Args:
            address(str): string containing either an IP address, FQDN, hostname, etc.
            port(int): the TCP port that the server is running on (Default value = 64738)
            certfile(str, optional): the path to the SSL certificate file in PEM format (Default value = None)
            keyfile(str, optional): the path to the certificate's key file (Default value = None)
            keypassword(str, optional): the secret key used to unlock the key file (Default value = None)

        Returns:
            None
        """
        self.address = address
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.keypassword = keypassword
        self.log = logging.getLogger(f'{self.username}@{self.address}:{self.port}')
        try:
            import opuslib
            self.audio_decoders = {AudioType.OPUS:    opuslib.Decoder(48000, 1)}
            self.audio_encoders = {AudioType.OPUS:    opuslib.Encoder(48000, 1, opuslib.APPLICATION_AUDIO)}
            self.audio_enabled = True
            self._fire_event(MumpyEvent.AUDIO_ENABLED)
        except Exception:
            self.log.warning('Failed to initialize Opus audio codec. Disabling audio')
            self._fire_event(MumpyEvent.AUDIO_DISABLED)
        self.connection_state = ConnectionState.CONNECTING
        self.tcp_connection_thread = Thread(target=self._start_tcp_connection)
        self.tcp_connection_thread.start()

    def disconnect(self):
        """
        Closes the connection to the server.

        Returns:
            None
        """
        if self.connection_state != ConnectionState.DISCONNECTED:
            try:
                self.ssl_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                self.ssl_socket.close()
            if self.udp_socket is not None:
                try:
                    self.udp_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                finally:
                    self.udp_socket.close()
        self.connection_state = ConnectionState.DISCONNECTED

    def get_users(self):
        """
        Returns:
            dict: a dictionary of User objects and IDs in the form users[id] = User()
        """
        return self.users

    def get_channels(self):
        """
        Returns:
            dict: a dictionary of Channel objects and IDs in the form ``<Mumpy>.get_channels()[id] = Channel()``
        """
        return self.channels

    def get_current_channel_id(self):
        """
        Returns:
            int: the ID of the channel the bot is currently in"""
        return self.get_user_by_id(self.session_id).channel_id

    def get_current_channel(self):
        """
        Returns:
            Channel: the Channel the bot is currently in."""
        return self.get_channel_by_id(self.get_current_channel_id())

    def get_channel_by_id(self, channel_id):
        """
        Args:
            channel_id(int): the ID of the channel

        Returns:
            Channel: the Channel identified by channel_id
        """
        return self.channels[channel_id]

    def get_channel_by_name(self, name):
        """
        Args:
            name(str): the name of the channel

        Returns:
            Channel: the Channel identified by name
        """
        for channel_id, channel in self.channels.items():
            if channel.name == name:
                return channel
        raise IndexError(f"Channel with the specified name does not exist: {name}")

    def get_user_by_id(self, session_id):
        """
        Args:
            session_id(int): the session ID of the user

        Returns:
            User: the User identified by session_id
        """
        return self.users[session_id]

    def get_user_by_name(self, name):
        """
        Args:
            name(str): the name of the user

        Returns:
            User: the User identified by name
        """
        for session_id, user in self.users.items():
            if user.name == name:
                return user
        raise IndexError(f"User with the specified name does not exist: {name}")

    def get_current_session_id(self):
        """
        Returns:
            int: the :py:class:`Mumpy` instance's session ID
        """
        return self.session_id

    def get_current_username(self):
        """
        Returns:
            str: the :py:class:`Mumpy` instance's username
        """
        return self.username

    def get_self_user(self):
        """
        Returns:
            User: the Mumpy instance's User object
        """
        return self.get_user_by_id(self.session_id)

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
        user = self.get_user_by_name(name)
        self.kick_user(user, reason=reason, ban=ban)

    def clear_all_audio_logs(self):
        """
        Clears every user's audio log, removing all received audio transmissions from memory.
        """
        for session_id, user in self.users.items():
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

    def _send_audio_packet_tcp(self, udppacket):
        """
        Sends a UDP audio packet to the server through the TCP socket.

        Args:
            udppacket(bytes): an unencrypted payload of audio data, formatted according to the Mumble protocol

        Returns:
            None
        """
        packet = struct.pack('!HL', MessageType.UDPTUNNEL, len(udppacket)) + udppacket
        self.ssl_socket.send(packet)

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
            to_encode = pcm[:frame_size*frame_width]
            pcm = pcm[frame_size*frame_width:]
            encoded_audio.append(self.audio_encoders[self.preferred_audio_codec].encode(to_encode, frame_size))
        header = struct.pack('!B', self.preferred_audio_codec << 5 | self.audio_target)
        for frame in encoded_audio[:-1]:
            sequence_number = VarInt(self.audio_sequence_number).encode()
            # TODO: positional info. struct.pack('!fff', 1.0, 2.0, 3.0)
            payload = VarInt(len(frame)).encode() + frame
            udp_packet = header + sequence_number + payload
            self._send_audio_packet_tcp(udp_packet)
            self.audio_sequence_number += 1
        # set the terminator bit for the last payload
        frame = encoded_audio[-1]
        sequence_number = VarInt(self.audio_sequence_number).encode()
        payload = VarInt(len(frame) | 0x2000).encode() + frame
        udp_packet = header + sequence_number + payload
        if self.connection_state == ConnectionState.CONNECTED_UDP:
            self._send_packet_udp(udp_packet)
        else:
            self._send_audio_packet_tcp(udp_packet)
        self.audio_sequence_number += 1
        self._fire_event(MumpyEvent.AUDIO_TRANSMISSION_SENT)

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
            message_payload.channel_id.append(self.get_current_channel_id())
        if channels:
            message_payload.channel_id.extend([channel.id for channel in channels])
        if users:
            message_payload.session.extend([user.session_id for user in users])
        self._send_payload(MessageType.TEXTMESSAGE, message_payload)
        self._fire_event(MumpyEvent.MESSAGE_SENT, message_payload)

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
            self.last_ping_time = ping_payload.timestamp

    def is_alive(self):
        """
        Returns:
            bool: True if bot is connected to the server
        """
        return self.connection_state != ConnectionState.DISCONNECTED

    def update_user_stats(self, user):
        """
        Queries the server for a User's stats.
        This function does not return anything. The server's response may fire the following events:
        - USER_STATS_UPDATED

        Args:
            user(User): the User to retrieve stats for

        Returns:
            None
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

        Events:
            - USER_COMMENT_UPDATED
            - USER_TEXTURE_UPDATED
            - CHANNEL_UPDATED
        """
        message_payload = mumble_pb2.RequestBlob()
        message_payload.session_texture.extend(user_textures)
        message_payload.session_comment.extend(user_comments)
        message_payload.channel_description.extend(channel_descriptions)
        self._send_payload(MessageType.REQUESTBLOB, message_payload)

    def move_user_to_channel(self, users, channel):
        """
        Moves each User in users to the specified Channel.

        Args:
            users(iterable): a list of Users to move
            channel(Channel): the channel to move the Users to

        Returns:
            None
        """
        for user in users:
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
        self.move_user_to_channel(self.get_self_user(), channel)

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

    def register_self(self):
        """
        Registers the Mumpy instance on the server.

        Returns:
            None
        """
        self.register_user(self.get_user_by_id(self.session_id))

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
