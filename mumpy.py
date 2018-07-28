from . import Mumble_pb2
from .constants import *
from .event_handler import EventHandler
from .user import User
from .varint import VarInt
from enum import Enum
from ocb.aes import AES
from ocb import OCB
from ssl import SSLContext, PROTOCOL_TLS
from threading import Thread
from time import time, sleep
import logging
import opuslib
import select
import socket
import struct
import wave

class MumpyEvent(Enum):
    CONNECTED = 'self_connected'
    DISCONNECTED = 'self_disconnected'
    CHANNEL_ADDED = 'channel_added'
    CHANNEL_REMOVED = 'channel_removed'
    USER_CONNECTED = 'user_connected'
    USER_DISCONNECTED = 'user_disconnected'
    USER_KICKED = 'user_kicked'
    USER_BANNED = 'user_banned'
    MESSAGE_RECEIVED = 'message_received'
    MESSAGE_SENT = 'message_sent'
    BANLIST_MODIFIED = 'banlist_modified'
    AUDIO_TRANSMISSION_RECEIVED = 'audio_transmission_received'
    AUDIO_TRANSMISSION_SENT = 'audio_transmission_sent'

class Mumpy:
    def __init__(self, username="mumble-bot", password=""):
        self.username = username
        self.password = password
        self.channels = {}
        self.users = {}
        self.session_id = None
        self.event_handlers = {}
        for event in MumpyEvent:
            self.event_handlers[event] = EventHandler()
        self.audio_decoders = { AUDIO_TYPE_OPUS:    opuslib.Decoder(48000, 1)}
        self.audio_encoders = { AUDIO_TYPE_OPUS:    opuslib.Encoder(48000, 1, opuslib.APPLICATION_AUDIO)}
        self.preferred_audio_codec = AUDIO_TYPE_OPUS
        self.audio_target = 0
        self.audio_sequence_number = 0
        self.sockets = []


    # message type 0
    def message_handler_Version(self, payload):
        message = Mumble_pb2.Version()
        message.ParseFromString(payload)
        server_version = struct.unpack('>HBB', struct.pack('>I', message.version))
        self.log.debug('Server version: {}.{}.{}'.format(*server_version))
        if PROTOCOL_VERSION[0] == server_version[0] and PROTOCOL_VERSION[1] == server_version[1]:
            self.log.debug('Sending our version: {}.{}.{}...'.format(*PROTOCOL_VERSION))
            version_response = Mumble_pb2.Version()
            version_response.version = struct.unpack('>I', struct.pack('>HBB', *PROTOCOL_VERSION))[0]
            version_response.release = RELEASE_STRING
            version_response.os = OS_STRING
            version_response.os_version = OS_VERSION_STRING
            self._send_payload(MESSAGE_TYPE_VERSION, version_response)
            self.log.debug('Sending authentication message...')
            authenticate_response = Mumble_pb2.Authenticate()
            authenticate_response.username = self.username
            authenticate_response.password = self.password
            #authenticate_response.tokens = ""
            authenticate_response.celt_versions.extend([-2147483637])
            authenticate_response.opus = True
            self._send_payload(MESSAGE_TYPE_AUTHENTICATE, authenticate_response)
        else:
            self.log.error('ERROR: Version mismatch! Our version is {}.{}.{}. Killing connection...'.format(*PROTOCOL_VERSION))


    # message type 1 -- UDPTunnel
    def message_handler_UDPTunnel(self, payload):
        header = struct.unpack('!B', payload[:1])[0]
        audio_type = (header & 0b11100000) >> 5
        target = header & 0b00011111
        payload = payload[1:]
        varint_reader = VarInt(payload)
        session_id = varint_reader.read_next()  # the user that sent the voice transmission
        sequence_number = varint_reader.read_next()
        print(sequence_number)
        if audio_type == AUDIO_TYPE_PING:
            return
        elif audio_type == AUDIO_TYPE_OPUS:
            size = varint_reader.read_next()
            if size & 0x2000:
                terminate = True
            else:
                terminate = False
            size = size & 0x1ff
            voice_frame = varint_reader.get_current_data()[:size]  # anything left after size is position data
            # TODO: Handle position data
            pcm = self.audio_decoders[audio_type].decode(voice_frame, frame_size=5760)  # 48000 / 100 * 12
            self._handle_audio(session_id, sequence_number, terminate, pcm)
        else:
            print(type)


    # message type 2 -- Authenticate
    # not sent by server, no handler needed


    # message type 3
    def message_handler_Ping(self, payload):
        message = Mumble_pb2.Ping()
        message.ParseFromString(payload)
        self.log.debug('Pong: {}'.format(message))


    # message type 4
    def message_handler_Reject(self, payload):
        message = Mumble_pb2.Reject()
        message.ParseFromString(payload)
        type = message.RejectType.Name(message.type)
        reason = message.reason
        self.log.error('Server rejected connection. Type: {}. Reason: {}'.format(type, reason))
        self.connected = False


    # message type 5
    def message_handler_ServerSync(self, payload):
        message = Mumble_pb2.ServerSync()
        message.ParseFromString(payload)
        self.session_id = message.session
        self.max_bandwidth = message.max_bandwidth
        self.server_welcome_text = message.welcome_text
        self.log.info('Connected to server')
        self._fire_event(MumpyEvent.CONNECTED, message)

    # message type 6
    def message_handler_ChannelRemove(self, payload):
        message = Mumble_pb2.ChannelRemove()
        message.ParseFromString(payload)
        try:
            channel_name = self.channels[message.channel_id]['name']
            self.log.debug('Removing channel ID {} ({})'.format(message.channel_id, channel_name))
            del(self.channels[message.channel_id])
        except:
            pass


    # message type 7
    def message_handler_ChannelState(self, payload):
        message = Mumble_pb2.ChannelState()
        message.ParseFromString(payload)
        if message.channel_id not in self.channels:
            self.channels[message.channel_id] = {}
        updated_fields = message.ListFields()
        for field, value in updated_fields:
            self.channels[message.channel_id][field.name] = value


    # message type 8
    def message_handler_UserRemove(self, payload):
        message = Mumble_pb2.UserRemove()
        message.ParseFromString(payload)
        if message.session == self.session_id:
            self.connected = False
        # murmur sends two UserRemove messages when someone is kicked or banned.
        # the first one contains the session, actor, reason, and ban fields.
        # the second message contains only the session ID of the victim.
        # When someone simply leaves the server, only the second message is sent
        try:
            session_username = self.users[message.session].name
            del(self.users[message.session])
        except:
            return
        if message.HasField('actor'):
            actor_username = self.users[message.actor].name
            if message.ban:
                action = "banned"
                self._fire_event(MumpyEvent.USER_BANNED, message)
            else:
                action = "kicked"
                self._fire_event(MumpyEvent.USER_KICKED, message)
            log_message = "{} {} {} (Reason: {})".format(actor_username, action, session_username, message.reason)
        else:
            log_message = "{} left the server".format(session_username)
            self._fire_event(MumpyEvent.USER_DISCONNECTED, message)
        self.log.debug(log_message)


    # message type 9
    def message_handler_UserState(self, payload):
        message = Mumble_pb2.UserState()
        message.ParseFromString(payload)
        try:
            self.users[message.session].update(message)
        except:
            self.users[message.session] = User(message)


    # message type 10
    def message_handler_BanList(self, payload):
        message = Mumble_pb2.BanList()
        message.ParseFromString(payload)
        self.log.debug("Received message type 10")
        self.log.debug(message)
        self._fire_event(MumpyEvent.BANLIST_MODIFIED, message)


    # message type 11
    def message_handler_TextMessage(self, payload):
        message = Mumble_pb2.TextMessage()
        message.ParseFromString(payload)
        sender_id = message.actor
        recipient_id = message.session
        channel_id = message.channel_id
        tree_id = message.tree_id
        message_body = message.message
        self.log.debug('Text message from {} to {} (channel: {}, tree_id: {}): {}'.format(sender_id, recipient_id, channel_id, tree_id, message_body))
        self._fire_event(MumpyEvent.MESSAGE_RECEIVED, message)


    # message type 12
    def message_handler_PermissionDenied(self, payload):
        message = Mumble_pb2.PermissionDenied()
        message.ParseFromString(payload)
        type = message.DenyType.Name(message.type)
        reason = message.reason
        self.log.debug('Permission denied. Type: {}. Reason: {}'.format(type, reason))


    # message type 13
    def message_handler_ACL(self, payload):
        message = Mumble_pb2.ACL()
        message.ParseFromString(payload)
        self.log.debug("Received message type 13")
        self.log.debug(message)


    # message type 14
    def message_handler_QueryUsers(self, payload):
        message = Mumble_pb2.QueryUsers()
        message.ParseFromString(payload)
        self.log.debug("Received message type 14")
        self.log.debug(message)


    # message type 15
    def message_handler_CryptSetup(self, payload):
        message = Mumble_pb2.CryptSetup()
        message.ParseFromString(payload)
        if message.HasField('key'):
            self.encryption_key = message.key
        if message.HasField('client_nonce'):
            self.client_nonce = message.client_nonce
        if message.HasField('server_nonce'):
           self.server_nonce = message.server_nonce
        aes = AES(128)
        #self.decrypter = OCB(aes)
        #self.decrypter.setKey(self.encryption_key)
        #self.decrypter.setNonce(
        self.encrypter = OCB(aes)
        self.encrypter.setKey(self.encryption_key)
        self._initialize_udp_socket()

    # handles incoming audio transmissions
    # session_id = (int) the sender of the audio
    # sequence = (int) which chunk of audio in the sequence this is
    # terminate = (boolean) True if this is the last chunk of audio in the sequence
    # pcm = (byte) the raw PCM audio data (signed 16-bit 48000Hz)
    def _handle_audio(self, session_id, sequence, terminate, pcm):
        user = self.users[session_id]
        user.audio_buffer += pcm
        if terminate:
            user.audio_log.append((time(), user.audio_buffer))
            user.audio_buffer = b''
            self._fire_event(MumpyEvent.AUDIO_TRANSMISSION_RECEIVED, user)


    '''
    Encrypts the data with OCB-AES128, using the key and nonce provided by the server.
    '''
    def _encrypt(self, data):
        self.encrypter.setNonce(self.client_nonce)
        tag, ciphertext = self.encrypter.encrypt(data, b'')
        return bytes(ciphertext)


    '''
    The process for establishing the UDP connection is:
    1. Client receives the CryptSetup message from the server, containing the encryption parameters
    2. Client sends an encrypted UDP ping packet (header + varint-encoded timestamp)
    3. Server echoes back the same data
    '''
    def _initialize_udp_socket(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_ping_packet =  b'\x20' + VarInt(int(time())).encode()
        self._send_packet_udp(udp_ping_packet)
        self.udp_socket.settimeout(3)
        try:
            response = self.udp_socket.recvfrom(1)
        except:
            self.udp_socket.close()
            self.log.warning("Timed out waiting for UDP ping response from server. Using TCP for audio traffic.")
            print("key={}\ncnonce={}\nsnonce={}\nplaintext={}\nciphertext={}".format(self.encryption_key, self.client_nonce, self.server_nonce, udp_ping_packet, self._encrypt(udp_ping_packet)))
            return
        print("Got UDP response:")
        print(response)


    def _send_packet_udp(self, data):
        self.udp_socket.sendto(self._encrypt(data), (self.address, self.port))


    def _start_connection_thread(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.address, self.port))
        ssl_context = SSLContext(PROTOCOL_TLS)
        self.ssl_socket = ssl_context.wrap_socket(sock)
        self.sockets.append(self.ssl_socket)
        self.ping_thread = Thread(target=self._ping_thread)
        self.ping_thread.start()
        self.message_buffer = b""
        while self.connected:
            inputs, outputs, exceptions = select.select(self.sockets, [], self.sockets)
            for input in inputs:
                try:
                    self.message_buffer += input.recv(4096)
                except OSError as e:
                    return False
                if len(self.message_buffer) == 0:  # connection closed by server
                    self.connected = False
                while len(self.message_buffer) >= 6:  # message header present
                    message_type = int.from_bytes(self.message_buffer[0:2], byteorder='big')
                    message_length = int.from_bytes(self.message_buffer[2:6], byteorder='big')
                    if len(self.message_buffer) >= 6 + message_length:
                        message_payload = self.message_buffer[6:6+message_length]
                    else:  # need to read more, buffer only contains partial packet
                        self.message_buffer += input.recv(4096)
                        continue
                    self.message_buffer = self.message_buffer[6+message_length:]

                    if message_type == MESSAGE_TYPE_VERSION:
                        self.message_handler_Version(message_payload)
                    elif message_type == MESSAGE_TYPE_UDPTUNNEL:
                        self.message_handler_UDPTunnel(message_payload)
                    elif message_type == MESSAGE_TYPE_PING:
                        self.message_handler_Ping(message_payload)
                    elif message_type == MESSAGE_TYPE_REJECT:
                        self.message_handler_Reject(message_payload)
                    elif message_type == MESSAGE_TYPE_SERVERSYNC:
                        self.message_handler_ServerSync(message_payload)
                    elif message_type == MESSAGE_TYPE_CHANNELREMOVE:
                        self.message_handler_ChannelRemove(message_payload)
                    elif message_type == MESSAGE_TYPE_CHANNELSTATE:
                        self.message_handler_ChannelState(message_payload)
                    elif message_type == MESSAGE_TYPE_USERREMOVE:
                        self.message_handler_UserRemove(message_payload)
                    elif message_type == MESSAGE_TYPE_USERSTATE:
                        self.message_handler_UserState(message_payload)
                    elif message_type == MESSAGE_TYPE_BANLIST:
                        self.message_handler_BanList(message_payload)
                    elif message_type == MESSAGE_TYPE_TEXTMESSAGE:
                        self.message_handler_TextMessage(message_payload)
                    elif message_type == MESSAGE_TYPE_PERMISSIONDENIED:
                        self.message_handler_PermissionDenied(message_payload)
                    elif message_type == MESSAGE_TYPE_ACL:
                        self.message_handler_ACL(message_payload)
                    elif message_type == MESSAGE_TYPE_QUERYUSERS:
                        self.message_handler_QueryUsers(message_payload)
                    elif message_type == MESSAGE_TYPE_CRYPTSETUP:
                        self.message_handler_CryptSetup(message_payload)
                    else:
                        self.log.warning('Received unhandled message type = {}'.format(message_type))
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


    def _send_payload(self, type, payload):
        packet = struct.pack('!HL', type, payload.ByteSize()) + payload.SerializeToString()
        try:
            self.ssl_socket.send(packet)
        except OSError as e:
            return False


    '''
    Adds the function as a handler for the specified event type.
    Example: my_mumpy.add_event_handler(EVENT_USER_KICKED, kickHandlerFunction)
    '''
    def add_event_handler(self, event_type, function):
        self.event_handlers[event_type].append(function)


    '''
    Connects starts the connection thread that connects to address:port.
    address is a string containing either an IP address, FQDN, hostname, etc.
    port is the TCP port that the server is running on (64738 by default)
    '''
    def connect(self, address, port=64738):
        self.address = address
        self.port = port
        self.log = logging.getLogger('{}@{}:{}'.format(self.username, self.address, self.port))
        self.connected = True
        self.connection_thread = Thread(target=self._start_connection_thread)
        self.connection_thread.start()
        self.log.debug('Started connection thread')


    '''
    Closes the connection to the server.
    '''
    def disconnect(self):
        self.ssl_socket.shutdown(socket.SHUT_RDWR)
        self.ssl_socket.close()
        self.connected = False


    '''
    Returns a dictionary of User objects and IDs in the form users[id] = User()
    '''
    def get_users(self):
        return self.users


    '''
    Returns a dictionary of channel names and IDs in the form channels[id] = name
    '''
    def get_channels(self):
        return self.channels


    '''
    Returns the ID of the channel the bot is currently in as an integer.
    '''
    def get_current_channel_id(self):
        return self.users[self.session_id].channel_id


    '''
    Returns the name of the channel the bot is currently in as a string.
    '''
    def get_current_channel_name(self):
        return self.get_channel_name_by_id(self.get_current_channel_id())


    '''
    Returns the name of the channel identified by id.
    '''
    def get_channel_name_by_id(self, id):
        return self.channels[id]['name']


    '''
    Returns the id of the channel identified by name.
    '''
    def get_channel_id_by_name(self, name):
        for id, channel in self.channels.items():
            if channel['name'] == name:
                return id
        return False


    '''
    Returns the User identified by session_id.
    '''
    def get_user_by_id(self, session_id):
        return self.users[session_id]


    '''
    Returns the User identified by name.
    '''
    def get_user_by_name(self, name):
        for session_id, user in self.users.items():
            if user.name == name:
                return user
        return False


    '''
    Returns the bot's session ID.
    '''
    def get_current_user_id(self):
        return self.session_id


    '''
    Returns the bot's username.
    '''
    def get_current_username(self):
        return self.username


    '''
    Kicks a User.
    Bans the User if ban is True.
    '''
    def kick_user(self, user, reason="", ban=False):
        kick_payload = Mumble_pb2.UserRemove()
        kick_payload.session = user.session_id
        kick_payload.reason = reason
        kick_payload.ban = ban
        self._send_payload(MESSAGE_TYPE_USERREMOVE, kick_payload)


    '''
    Kicks a user identified by name.
    Bans the user if ban is True.
    '''
    def kick_user_by_name(self, name, reason="", ban=False):
        user = self.get_user_by_name(name)
        self.kick_user(user, reason=reason, ban=ban)


    '''
    Returns a List of all the completed audio transmissions from the user identified by name.
    Each element in the list is a byte string containing the raw PCM audio data from that transmission.
    '''
    def get_user_audio_log(self, name):
        return self.get_user_by_name(name).audio_log


    '''
    Clears the audio log of a specific user identified by name.
    '''
    def clear_user_audio_log(self, name):
        user = self.get_user_by_name(name)
        user.audio_log = []


    '''
    Clears every user's audio log, removing all received audio transmissions from memory.
    '''
    def clear_all_audio_logs(self):
        for session_id, user in self.users.items():
            user.audio_log = []


    '''
    Converts the raw PCM audio data to WAV and saves it to a file.
    '''
    def export_to_wav(self, pcm, filename):
        f = wave.open(filename, 'wb')
        f.setnchannels(1)  # mono
        f.setsampwidth(2)  # 16-bit
        f.setframerate(48000) # 48KHz
        f.writeframes(pcm)
        f.close()


    '''
    Converts all audio logs from all users to WAV and saves them to separate files.
    Clears all audio logs once the audio has been saved.
    '''
    def export_audio_logs_to_wav(self, folder='./'):
        for session_id, user in self.users.items():
            counter = 1
            base_filename = folder + user.name + '_'
            for timestamp, pcm in user.audio_log:
                filename = base_filename + str(int(timestamp)) + '.wav'
                self.export_to_wav(pcm, filename)
                counter += 1
            user.audio_log = []


    '''
    Sends a complete, unencrypted UDP audio packet to the server over the TCP socket.
    '''
    def _send_audio_packet_tcp(self, udppacket):
        packet = struct.pack('!HL', MESSAGE_TYPE_UDPTUNNEL, len(udppacket)) + udppacket
        try:
            self.ssl_socket.send(packet)
        except OSError as e:
            return False


    '''
    Encodes raw PCM data using the preferred audio codec and transmits it to the server.
    '''
    def send_audio(self, pcm, sample_rate=48000, sample_width=2):
        frame_size = int(sample_rate / 100)
        frame_width = sample_width
        encoded_audio = []
        while len(pcm) > 0:
            to_encode = pcm[:frame_size*frame_width]
            pcm = pcm[frame_size*frame_width:]
            encoded_audio.append(self.audio_encoders[self.preferred_audio_codec].encode(to_encode, frame_size))
        header = struct.pack('!B', AUDIO_TYPE_OPUS << 5 | self.audio_target)
        for frame in encoded_audio[:-1]:
            sequence_number = VarInt(self.audio_sequence_number).encode()
            # TODO: positional info. struct.pack('!fff', 1.0, 2.0, 3.0)
            payload = VarInt(len(frame)).encode() + frame
            udppacket = header + sequence_number + payload
            self._send_audio_packet_tcp(udppacket)
            self.audio_sequence_number += 1
        # set the terminator bit for the last payload
        sequence_number = VarInt(self.audio_sequence_number).encode()
        payload = VarInt(len(frame) | 0x2000).encode() + frame
        udppacket = header + sequence_number + payload
        self._send_audio_packet_tcp(udppacket)
        self.audio_sequence_number += 1
        self._fire_event(MumpyEvent.AUDIO_TRANSMISSION_SENT)


    '''
    Reads the raw PCM data and then sends it as an audio transmission.
    '''
    def play_wav(self, filename):
        f = wave.open(filename, 'rb')
        total_frames = f.getnframes()
        samples = f.readframes(total_frames)
        freq = f.getframerate()
        width = f.getsampwidth()
        f.close()
        self.send_audio(samples, freq, width)


    '''
    Sends a text message to each channel in the list channels, and to each user in the list users.
    If no channels or users are specified, sends the message to the bot's current channel.
    '''
    def text_message(self, message, channels=[], users=[]):
        message_payload = Mumble_pb2.TextMessage()
        message_payload.message = message
        if len(channels) == 0 and len(users) == 0:
            message_payload.channel_id.append(self.get_current_channel_id())
        if channels:
            message_payload.channel_id += channels
        if users:
            message_payload.session += [user.session_id for user in users]
        self._send_payload(MESSAGE_TYPE_TEXTMESSAGE, message_payload)
        self._fire_event(MumpyEvent.MESSAGE_SENT, message_payload)


    '''
    Sends a Ping packet to the server, as specified by the Mumble protocol.
    '''
    def ping(self):
        ping_payload = Mumble_pb2.Ping()
        ping_payload.timestamp = int(time())
        self._send_payload(MESSAGE_TYPE_PING, ping_payload)
        self.last_ping_time = ping_payload.timestamp


    '''
    Returns True if bot is connected to the server.
    '''
    def is_alive(self):
        return self.connected
