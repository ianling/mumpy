from sys import version as PYTHON_VERSION
import platform


class MumpyEnum(type):
    """
    Very barebones enum. Simply allows you to iterate through all of the values in the enum.
    """
    def __iter__(self):
        for attr in dir(self):
            if not attr.startswith("__"):
                yield getattr(self, attr)


class MessageType(metaclass=MumpyEnum):
    """
    The Mumble protocol protobuf message types.
    Additional information about these can be found in the official Mumble protobuf definition file:
    https://github.com/mumble-voip/mumble/blob/master/src/Mumble.proto
    """
    VERSION = 0
    UDPTUNNEL = 1
    AUTHENTICATE = 2
    PING = 3
    REJECT = 4
    SERVERSYNC = 5
    CHANNELREMOVE = 6
    CHANNELSTATE = 7
    USERREMOVE = 8
    USERSTATE = 9
    BANLIST = 10
    TEXTMESSAGE = 11
    PERMISSIONDENIED = 12
    ACL = 13
    QUERYUSERS = 14
    CRYPTSETUP = 15
    CONTEXTACTIONMODIFY = 16
    CONTEXTACTION = 17
    USERLIST = 18
    VOICETARGET = 19
    PERMISSIONQUERY = 20
    CODECVERSION = 21
    USERSTATS = 22
    REQUESTBLOB = 23
    SERVERCONFIG = 24
    SUGGESTCONFIG = 25


class Permission(metaclass=MumpyEnum):
    """
    The Mumble protocol permissions.
    """
    NONE = 0x0
    WRITE = 0x1
    TRAVERSE = 0x2
    ENTER = 0x4
    SPEAK = 0x8
    MUTE_DEAFEN = 0x10
    MOVE = 0x20
    MAKE_CHANNEL = 0x40
    LINK_CHANNEL = 0x80
    WHISPER = 0x100
    TEXT_MESSAGE = 0x200
    MAKE_TEMP_CHANNEL = 0x400

    # Root channel only
    KICK = 0x10000
    BAN = 0x20000
    REGISTER = 0x40000
    SELF_REGISTER = 0x80000

    CACHED = 0x8000000
    ALL = 0xf07ff


class PresetVoiceTarget(metaclass=MumpyEnum):
    DEFAULT = 0
    SERVER_LOOPBACK = 31


class AudioType(metaclass=MumpyEnum):
    """
    The audio codecs supported by the Mumble protocol.
    """
    CELT_ALPHA = 0
    PING = 1
    SPEEX = 2
    CELT_BETA = 3
    OPUS = 4


class ConnectionState(metaclass=MumpyEnum):
    """
    The different states the connection to a server can be in.
    """
    DISCONNECTED = 'disconnected'
    CONNECTING = 'connecting'
    AUTHENTICATING = 'authenticating'
    CONNECTED_NO_UDP = 'connected_no_udp'
    CONNECTED_UDP = 'connected_udp'
    DISCONNECTING = 'disconnecting'


class EventType(metaclass=MumpyEnum):
    """
    The event types supported by Mumpy.
    """

    CONNECTED = 'self_connected'
    """
    Fired when the client has connected and authenticated successfully.
    """

    DISCONNECTED = 'self_disconnected'
    """
    Fired when the client has disconnected from the server. May be preceded by a USER_KICKED and a USER_BANNED event.
    """

    UDP_CONNECTED = 'udp_connected'
    """
    Fired when the client has successfully established a UDP connection to the server
    """

    UDP_DISCONNECTED = 'udp_disconnected'
    """
    Fired when the client has lost or intentionally ended the UDP connection.
    This implies that audio communications have reverted back to using the TCP connection.
    """

    CHANNEL_ADDED = 'channel_added'
    """
    Fired when a channel is added to the server.
    """

    CHANNEL_UPDATED = 'channel_updated'
    """
    Fired when a channel is updated or modified in some way.
    """

    CHANNEL_REMOVED = 'channel_removed'
    """
    Fired when a channel is removed from the server.
    """

    CHANNEL_PERMISSIONS_UPDATED = 'channel_permissions_updated'
    """
    Fired when the Mumpy instance's permissions in a channel have changed.
    """

    USER_CONNECTED = 'user_connected'
    """
    Fired when someone else connects to the server.
    """

    USER_DISCONNECTED = 'user_disconnected'
    """
    Fired when someone else disconnects from the server. May be preceded by a USER_KICKED and a USER_BANNED event.
    """

    USER_KICKED = 'user_kicked'
    """
    Fired when anyone is kicked from the server.
    """

    USER_BANNED = 'user_banned'
    """
    Fired when anyone is banned from the server.
    """

    USER_STATS_UPDATED = 'user_stats_updated'
    """
    Fired when updated stats about a user are received.
    This happens after the client specifically requests stats about a user.
    """

    USER_REGISTERED = 'user_registered'
    """
    Fired when a user registers on the server.
    """

    USER_UNREGISTERED = 'user_unregistered'
    """
    Fired when a user is unregistered on the server.
    """

    USER_COMMENT_UPDATED = 'user_comment_updated'
    """
    Fired when a user changes their comment.
    """

    USER_AVATAR_UPDATED = 'user_avatar_updated'
    """
    Fired when a user changes their avatar.
    """

    USER_SELF_MUTED = 'user_self_muted'
    """
    Fired when a user mutes themselves.
    """

    USER_SELF_DEAFENED = 'user_self_deafened'
    """
    Fired when a user deafens themselves.
    """

    USER_SELF_UNMUTED = 'user_self_unmuted'
    """
    Fired when a user unmutes themselves.
    """

    USER_SELF_UNDEAFENED = 'user_self_undeafened'
    """
    Fired when a user undeafens themselves.
    """

    USER_MUTED = 'user_muted'
    """
    Fired when a user is muted server side (e.g. by a server admin).
    """

    USER_DEAFENED = 'user_deafened'
    """
    Fired when a user is deafened server side (e.g. by a server admin).
    """

    USER_UNMUTED = 'user_unmuted'
    """
     Fired when a user is unmuted server side (e.g. by a server admin).
    """

    USER_UNDEAFENED = 'user_undeafened'
    """
    Fired when a user is undeafened server side (e.g. by a server admin).
    """

    USER_RECORDING = 'user_recording'
    """
    Fired when a user starts recording.
    """

    USER_STOPPED_RECORDING = 'user_stopped_recording'
    """
    Fired when a user stops recording.
    """

    MESSAGE_RECEIVED = 'message_received'
    """
    Fired when a text message is received.
    """

    MESSAGE_SENT = 'message_sent'
    """
    Fired when the client sends a text message.
    """

    BANLIST_MODIFIED = 'banlist_modified'
    """
    Fired when the server's ban list is modified.
    """

    REGISTERED_USER_LIST_RECEIVED = 'registered_user_list_received'
    """
    Fired when the client receives the list of registered users on the server. These are stored in <Mumpy instance>.registered_users
    """

    AUDIO_TRANSMISSION_RECEIVED = 'audio_transmission_received'
    """
    Fired when the client has received a complete audio transmission from the server.
    """

    AUDIO_TRANSMISSION_SENT = 'audio_transmission_sent'
    """
    Fired when the client has sent a complete audio transmission to the server.
    """

    AUDIO_DISABLED = 'audio_disabled'
    """
    Fired when the client disables audio processing.
    This happens when the client fails to initialize the chosen audio codec,
    or does not support any of the server's audio codecs.
    """

    AUDIO_ENABLED = 'audio_enabled'
    """
    Fired when the client enables audio processing.
    This happens when the client initially connects to the server and successfully initializes an audio codec.
    """


PROTOCOL_VERSION = (1, 2, 19)  # (major, minor, patch)
RELEASE_STRING = "MumPy 1.0b"
OS_STRING = RELEASE_STRING
OS_VERSION_STRING = "Python %s - %s %s" % (PYTHON_VERSION, platform.system(), platform.release())

PING_INTERVAL = 10  # how often to send Ping messages to the server, in seconds
