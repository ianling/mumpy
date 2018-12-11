import sys
import traceback

from . import mumble_pb2
from .constants import MessageType, MumpyEvent, AudioType, PROTOCOL_VERSION, OS_VERSION_STRING, RELEASE_STRING,\
    OS_STRING, PING_INTERVAL
from .event_handler import EventHandler
from .mumblecrypto import MumbleCrypto
from .user import User
from .varint import VarInt
from ssl import SSLContext, PROTOCOL_TLS
from threading import Thread
from time import time, sleep
import logging
import opuslib
import select
import socket
import struct
import wave


# TODO: add function to manually kill UDP connection and switch back to TCP

class Mumpy:
    def __init__(self, username="mumble-bot", password=""):
        self.username = username
        self.password = password
        self.channels = {}
        self.users = {}
        self.session_id = None
        self.message_handlers = {MessageType.VERSION:       self.message_handler_Version,
                                 MessageType.UDPTUNNEL:     self.message_handler_UDPTunnel,
                                 MessageType.PING:          self.message_handler_Ping,
                                 MessageType.REJECT:        self.message_handler_Reject,
                                 MessageType.SERVERSYNC:    self.message_handler_ServerSync,
                                 MessageType.CHANNELREMOVE: self.message_handler_ChannelRemove,
                                 MessageType.CHANNELSTATE:  self.message_handler_ChannelState,
                                 MessageType.USERREMOVE:    self.message_handler_UserRemove,
                                 MessageType.USERSTATE:     self.message_handler_UserState,
                                 MessageType.BANLIST:       self.message_handler_BanList,
                                 MessageType.TEXTMESSAGE:   self.message_handler_TextMessage,
                                 MessageType.PERMISSIONDENIED: self.message_handler_PermissionDenied,
                                 MessageType.ACL:           self.message_handler_ACL,
                                 MessageType.QUERYUSERS:    self.message_handler_QueryUsers,
                                 MessageType.CRYPTSETUP:    self.message_handler_CryptSetup,
                                 # MessageType.CONTEXTACTIONMODIFY: self.message_handler_ContextActionModify,
                                 # MessageType.CONTEXTACTION: self.message_handler_ContextAction,
                                 # MessageType.USERLIST: self.message_handler_UserList,
                                 # MessageType.VOICETARGET: self.message_handler_VoiceTarget,
                                 # MessageType.PERMISSIONQUERY: self.message_handler_PermissionQuery,
                                 # MessageType.CODECVERSION: self.message_handler_CodecVersion,
                                 MessageType.USERSTATS:     self.message_handler_UserStats,
                                 MessageType.SERVERCONFIG:  self.message_handler_ServerConfig,
                                 MessageType.SUGGESTCONFIG: self.message_handler_SuggestConfig,
                                 }
        self.event_handlers = {}
        for event in MumpyEvent:
            self.event_handlers[event] = EventHandler()
        self.address = None
        self.port = None
        self.log = None
        self.tcp_connection_thread = None
        self.udp_connection_thread = None
        # TODO: wrap this in a try/except to make sure they have opus stuff installed. disable audio if they don't
        self.audio_decoders = {AudioType.OPUS:    opuslib.Decoder(48000, 1)}
        self.audio_encoders = {AudioType.OPUS:    opuslib.Encoder(48000, 1, opuslib.APPLICATION_AUDIO)}
        self.preferred_audio_codec = AudioType.OPUS
        self.audio_target = 0
        self.audio_sequence_number = 0
        self.connected = False
        self.use_udp = False
        self.max_bandwidth = None
        self.crypto = None
        self.encryption_key = None
        self.client_nonce = None
        self.server_nonce = None
        self.last_ping_time = 0
        self.max_message_length = None
        self.max_image_message_length = None
        self.server_allow_html = False

    # message type 0
    def message_handler_Version(self, payload):
        message = mumble_pb2.Version()
        message.ParseFromString(payload)
        server_version = struct.unpack('>HBB', struct.pack('>I', message.version))
        self.log.debug('Server version: {}.{}.{}'.format(*server_version))
        if PROTOCOL_VERSION[0] == server_version[0] and PROTOCOL_VERSION[1] == server_version[1]:
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
    def message_handler_UDPTunnel(self, payload):
        self._handle_audio(payload)

    # message type 2 -- Authenticate
    # not sent by server, no handler needed

    # message type 3
    def message_handler_Ping(self, payload):
        message = mumble_pb2.Ping()
        message.ParseFromString(payload)
        self.log.debug('Pong: {}'.format(message))

    # message type 4
    def message_handler_Reject(self, payload):
        message = mumble_pb2.Reject()
        message.ParseFromString(payload)
        rejection_type = message.RejectType.Name(message.type)
        reason = message.reason
        self.log.error(f'Server rejected connection. Type: {rejection_type}. Reason: {reason}')
        self.connected = False

    # message type 5
    def message_handler_ServerSync(self, payload):
        message = mumble_pb2.ServerSync()
        message.ParseFromString(payload)
        self.session_id = message.session
        self.max_bandwidth = message.max_bandwidth
        self.log.info('Connected to server')
        self.udp_connection_thread = Thread(target=self._start_udp_connection)
        self.udp_connection_thread.start()
        self._fire_event(MumpyEvent.CONNECTED, message)

    # message type 6
    def message_handler_ChannelRemove(self, payload):
        message = mumble_pb2.ChannelRemove()
        message.ParseFromString(payload)
        try:
            channel_name = self.get_channel_name_by_id(message.channel_id)
            self.log.debug(f'Removing channel ID {message.channel_id} ({channel_name})')
            del(self.channels[message.channel_id])
        except Exception:
            pass

    # message type 7
    def message_handler_ChannelState(self, payload):
        message = mumble_pb2.ChannelState()
        message.ParseFromString(payload)
        if message.channel_id not in self.channels:
            self.channels[message.channel_id] = {}
        updated_fields = message.ListFields()
        for field, value in updated_fields:
            self.channels[message.channel_id][field.name] = value

    # message type 8
    def message_handler_UserRemove(self, payload):
        """
        Murmur sends two UserRemove messages when someone is kicked or banned.
        The first one contains the session, actor, reason, and ban fields.
        The second message contains only the session ID of the victim.
        However, when someone simply leaves the server, only the second message is sent.
        """
        message = mumble_pb2.UserRemove()
        message.ParseFromString(payload)
        if message.session == self.session_id:
            self.connected = False
        try:
            session_username = self.get_user_by_id(message.session).name
            del(self.users[message.session])
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
            log_message = f"{session_username} left the server"
            self._fire_event(MumpyEvent.USER_DISCONNECTED, message)
        self.log.debug(log_message)

    # message type 9
    def message_handler_UserState(self, payload):
        message = mumble_pb2.UserState()
        message.ParseFromString(payload)
        try:
            self.get_user_by_id(message.session).update(message)
        except Exception:
            self.users[message.session] = User(message)

    # message type 10
    def message_handler_BanList(self, payload):
        message = mumble_pb2.BanList()
        message.ParseFromString(payload)
        self.log.debug("Received message type 10")
        self.log.debug(message)
        self._fire_event(MumpyEvent.BANLIST_MODIFIED, message)

    # message type 11
    def message_handler_TextMessage(self, payload):
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
    def message_handler_PermissionDenied(self, payload):
        message = mumble_pb2.PermissionDenied()
        message.ParseFromString(payload)
        type = message.DenyType.Name(message.type)
        reason = message.reason
        self.log.debug(f'Permission denied. Type: {type}. Reason: {reason}')

    # message type 13
    def message_handler_ACL(self, payload):
        message = mumble_pb2.ACL()
        message.ParseFromString(payload)
        self.log.debug("Received message type 13")
        self.log.debug(message)

    # message type 14
    def message_handler_QueryUsers(self, payload):
        message = mumble_pb2.QueryUsers()
        message.ParseFromString(payload)
        self.log.debug("Received message type 14")
        self.log.debug(message)

    # message type 15
    def message_handler_CryptSetup(self, payload):
        message = mumble_pb2.CryptSetup()
        message.ParseFromString(payload)
        if message.HasField('key'):
            self.encryption_key = message.key
        if message.HasField('client_nonce'):
            self.client_nonce = message.client_nonce
        if message.HasField('server_nonce'):
            self.server_nonce = message.server_nonce
        self.crypto = MumbleCrypto(self.encryption_key, self.client_nonce, self.server_nonce)

    # message type 22
    def message_handler_UserStats(self, payload):
        message = mumble_pb2.UserStats()
        message.ParseFromString(payload)
        user = self.get_user_by_id(message.session)
        user.update(message, prefix='stats')
        self._fire_event(MumpyEvent.USER_STATS_UPDATED, message)

    # message type 23 -- RequestBlob
    # not sent by server, no handler needed
    # TODO: handle sending these to the server

    # message type 24
    def message_handler_ServerConfig(self, payload):
        message = mumble_pb2.ServerConfig()
        message.ParseFromString(payload)
        self.max_message_length = message.message_length
        self.max_image_message_length = message.image_message_length
        self.server_allow_html = message.allow_html

    # message type 25
    def message_handler_SuggestConfig(self, payload):
        # nothing important in this message type, maybe implement in the future
        pass

    def _handle_audio(self, payload):
        """
        handles incoming audio transmissions
        session_id = (int) the sender of the audio
        sequence = (int) which chunk of audio in the sequence this is
        terminate = (boolean) True if this is the last chunk of audio in the sequence
        pcm = (byte) the raw PCM audio data (signed 16-bit 48000Hz)
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
        """
        tag, ciphertext = self.crypto.encrypt(data)
        ciphertext = self.crypto.client_nonce[0:1] + tag[0:3] + ciphertext
        return bytes(ciphertext)

    def _decrypt(self, data):
        """
        Decrypts the data with OCB-AES128, using the key and nonce provided by the server.
        """
        nonce_byte = data[0:1]
        tag = data[1:4]
        data = data[4:]
        decryption_tag, plaintext = self.crypto.decrypt(data, nonce_byte)
        assert tag == decryption_tag[0:3], f"Decryption tag does not match, decryption failed (my nonce: {self.crypto.server_nonce[0]} received nonce: {ord(nonce_byte)}"
        return plaintext

    def _start_udp_connection(self):
        """
        The process for establishing the UDP connection is:
        1. Client receives the CryptSetup message from the server, containing the encryption parameters
        2. Client sends an encrypted UDP ping packet (header + varint-encoded timestamp)
        3. Server echoes back the same data
        4. Voice data can now be sent and received via UDP
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
        self.use_udp = True
        self.log.debug("Using UDP for audio traffic")
        self._fire_event(MumpyEvent.UDP_CONNECTED)

        while self.use_udp:
            inputs, outputs, exceptions = select.select([self.udp_socket], [], [])
            for input_socket in inputs:
                udp_message_buffer, sender = input_socket.recvfrom(2048)
                if len(udp_message_buffer) == 0:  # connection closed by server
                    self.log.error("UDP socket returned 0 bytes, closing connection")
                    self.use_udp = False
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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.address, self.port))
        ssl_context = SSLContext(PROTOCOL_TLS)
        self.ssl_socket = ssl_context.wrap_socket(sock)
        self.ping_thread = Thread(target=self._ping_thread)
        self.ping_thread.start()
        self.tcp_message_buffer = b""
        while self.connected:
            inputs, outputs, exceptions = select.select([self.ssl_socket], [], [])
            for input_socket in inputs:
                try:
                    self.tcp_message_buffer += input_socket.recv(4096)
                except OSError:
                    self.log.error("TCP socket died")
                if len(self.tcp_message_buffer) == 0:  # connection closed by server
                    self.log.error("TCP socket returned 0 bytes, closing connection")
                    self.connected = False
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
                        self.log.warning(f'Received unhandled message type = {message_type}, message = {message_payload}')
        else:
            self._fire_event(MumpyEvent.DISCONNECTED)

    def _fire_event(self, event_type, message=None):
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
        Example: my_mumpy.add_event_handler(EVENT_USER_KICKED, kickHandlerFunction)
        """
        self.event_handlers[event_type].append(function_handle)

    def connect(self, address, port=64738):
        """
        Connects starts the connection thread that connects to address:port.
        address is a string containing either an IP address, FQDN, hostname, etc.
        port is the TCP port that the server is running on (64738 by default)
        """
        self.address = address
        self.port = port
        self.log = logging.getLogger(f'{self.username}@{self.address}:{self.port}')
        self.connected = True
        self.tcp_connection_thread = Thread(target=self._start_tcp_connection)
        self.tcp_connection_thread.start()
        self.log.debug('Started connection thread')

    def disconnect(self):
        """
        Closes the connection to the server.
        """
        self.ssl_socket.shutdown(socket.SHUT_RDWR)
        self.ssl_socket.close()
        if self.udp_socket is not None:
            self.udp_socket.shutdown(socket.SHUT_RDWR)
            self.udp_socket.close()
        self.connected = False
        self.use_udp = False

    def get_users(self):
        """
        Returns a dictionary of User objects and IDs in the form users[id] = User()
        """
        return self.users

    def get_channels(self):
        """
        Returns a dictionary of channel names and IDs in the form channels[id] = name
        """
        return self.channels

    def get_current_channel_id(self):
        """
        Returns the ID of the channel the bot is currently in as an integer.
        """
        return self.users[self.session_id].channel_id

    def get_current_channel_name(self):
        """
        Returns the name of the channel the bot is currently in as a string.
        """
        return self.get_channel_name_by_id(self.get_current_channel_id())

    def get_channel_name_by_id(self, channel_id):
        """
        Returns the name of the channel identified by id.
        """
        return self.channels[channel_id]['name']

    def get_channel_id_by_name(self, name):
        """
        Returns the id of the channel identified by name.
        """
        for channel_id, channel in self.channels.items():
            if channel['name'] == name:
                return channel_id
        raise IndexError(f"Channel with the specified name does not exist: {name}")

    def get_user_by_id(self, session_id):
        """
        Returns the User identified by session_id.
        """
        return self.users[session_id]

    def get_user_by_name(self, name):
        """
        Returns the User identified by name.
        """
        for session_id, user in self.users.items():
            if user.name == name:
                return user
        return False

    def get_current_user_id(self):
        """
        Returns the bot's session ID.
        """
        return self.session_id

    def get_current_username(self):
        """
        Returns the bot's username.
        """
        return self.username

    def kick_user(self, user, reason="", ban=False):
        """
        Kicks a User.
        Bans the User if ban is True.
        """
        kick_payload = mumble_pb2.UserRemove()
        kick_payload.session = user.session_id
        kick_payload.reason = reason
        kick_payload.ban = ban
        self._send_payload(MessageType.USERREMOVE, kick_payload)

    def kick_user_by_name(self, name, reason="", ban=False):
        """
        Kicks a user identified by name.
        Bans the user if ban is True.
        """
        user = self.get_user_by_name(name)
        self.kick_user(user, reason=reason, ban=ban)

    def get_user_audio_log(self, name):
        """
        Returns a List of all the completed audio transmissions from the user identified by name.
        Each element in the list is a byte string containing the raw PCM audio data from that transmission.
        """
        return self.get_user_by_name(name).audio_log

    def clear_user_audio_log(self, name):
        """
        Clears the audio log of a specific user identified by name.
        """
        user = self.get_user_by_name(name)
        user.audio_log = []

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
        """
        packet = struct.pack('!HL', MessageType.UDPTUNNEL, len(udppacket)) + udppacket
        self.ssl_socket.send(packet)

    def send_audio(self, pcm, sample_rate=48000, sample_width=2):
        """
        Encodes raw PCM data using the preferred audio codec and transmits it to the server.
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
        self._send_audio_packet_tcp(udp_packet)
        self.audio_sequence_number += 1
        self._fire_event(MumpyEvent.AUDIO_TRANSMISSION_SENT)

    def play_wav(self, filename):
        """
        Reads the raw PCM data and then sends it as an audio transmission.
        """
        f = wave.open(filename, 'rb')
        total_frames = f.getnframes()
        samples = f.readframes(total_frames)
        freq = f.getframerate()
        width = f.getsampwidth()
        f.close()
        self.send_audio(samples, freq, width)

    def text_message(self, message, channels=[], users=[]):
        """
        Sends a text message to each channel in the list channels, and to each user in the list users.
        If no channels or users are specified, sends the message to the bot's current channel.

        :param message: (str) the text message
        :param channels: (iterable) a list of channels to send the message to
        :param users: (iterable) a list of users to send the message to
        """
        message_payload = mumble_pb2.TextMessage()
        message_payload.message = message
        if len(channels) == 0 and len(users) == 0:
            message_payload.channel_id.append(self.get_current_channel_id())
        if channels:
            message_payload.channel_id += channels
        if users:
            message_payload.session += [user.session_id for user in users]
        self._send_payload(MessageType.TEXTMESSAGE, message_payload)
        self._fire_event(MumpyEvent.MESSAGE_SENT, message_payload)

    def ping(self, udp=False):
        """
        Sends a Ping packet to the server, as specified by the Mumble protocol.

        :param udp: (boolean) if True, sends a UDP ping. Otherwise, sends a TCP ping.
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
        Returns True if bot is connected to the server.
        """
        return self.connected

    def update_user_stats(self, user):
        message_payload = mumble_pb2.UserStats()
        message_payload.session = user.session_id
        self._send_payload(MessageType.USERSTATS, message_payload)
