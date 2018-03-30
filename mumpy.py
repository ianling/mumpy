from . import Mumble_pb2
from .event_handler import EventHandler
from .constants import *
from enum import Enum
from ssl import SSLContext, PROTOCOL_TLS
from threading import Thread
from time import time, sleep
import logging
import select
import socket
import struct


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
    # not used, no handler needed

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
        # When someone leaves the server, only the second message is sent
        try:
            session_username = self.users[message.session]['name']
            del(self.users[message.session])
        except:
            return
        if message.HasField('actor'):
            actor_username = self.users[message.actor]['name']
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
        if message.session not in self.users:
            self.users[message.session] = {}
        updated_fields = message.ListFields()
        for field, value in updated_fields:
            self.users[message.session][field.name] = value
        if 'channel_id' not in self.users[message.session]:
            self.users[message.session]['channel_id'] = 0


    # message type 10
    def message_handler_BanList(self, payload):
        message = Mumble_pb2.BanList()
        message.ParseFromString(payload)
        self.log.debug("Received message type 10")
        self.log.debug(message)


    # message type 11
    def message_handler_TextMessage(self, payload):
        message = Mumble_pb2.TextMessage()
        message.ParseFromString(payload)
        sender_id = message.actor
        recipient = message.session
        channel_id = message.channel_id
        tree_id = message.tree_id
        message_body = message.message
        self.log.debug('Text message from {} to {} (channel: {}, tree_id: {}): {}'.format(sender_id, recipient, channel_id, tree_id, message_body))
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
        self.log.debug("Received message type 15 (CryptSetup)")


    def _start_connection_thread(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.address, self.port))
        ssl_context = SSLContext(PROTOCOL_TLS)
        self.ssl_socket = ssl_context.wrap_socket(sock)
        self.ping_thread = Thread(target=self._ping_thread)
        self.ping_thread.start()
        self.message_buffer = b""
        while self.connected:
            inputs, outputs, exceptions = select.select([self.ssl_socket], [], [self.ssl_socket])
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


    def _fire_event(self, event_type, message=""):
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

    def disconnect(self):
        self.ssl_socket.shutdown(socket.SHUT_RDWR)
        self.ssl_socket.close()
        self.connected = False


    def get_users(self):
        return self.users

    def get_channels(self):
        return self.channels


    '''
    Returns the ID of the channel the bot is currently in as an integer.
    '''
    def get_current_channel_id(self):
        return self.users[self.session_id]['channel_id']


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
    Returns the name of the user identified by id.
    '''
    def get_user_name_by_id(self, id):
        return self.users[id]['name']

    '''
    Returns the id of the user identified by name.
    '''
    def get_user_id_by_name(self, name):
        for id, user in self.users.items():
            if user['name'] == name:
                return id
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
    Kicks a user identified by id.
    Bans the user if ban is True.
    '''
    def kick_user_by_id(self, id, reason="", ban=False):
        kick_payload = Mumble_pb2.UserRemove()
        kick_payload.session = id
        kick_payload.reason = reason
        kick_payload.ban = ban
        self._send_payload(MESSAGE_TYPE_USERREMOVE, kick_payload)

    '''
    Kicks a user identified by name.
    Bans the user if ban is True.
    '''
    def kick_user_by_name(self, name, reason="", ban=False):
        id = self.get_user_id_by_name(name)
        self.kick_user_by_id(id, reason=reason, ban=ban)

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
            message_payload.session += users
        self._send_payload(MESSAGE_TYPE_TEXTMESSAGE, message_payload)


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
