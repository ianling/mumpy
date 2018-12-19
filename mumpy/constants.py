from sys import version as PYTHON_VERSION
import platform


class MumpyEnum(type):
    def __iter__(self):
        for attr in dir(self):
            if not attr.startswith("__"):
                yield getattr(self, attr)


class MessageType(metaclass=MumpyEnum):
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


class AudioType:
    CELT_ALPHA = 0
    PING = 1
    SPEEX = 2
    CELT_BETA = 3
    OPUS = 4


class MumpyEvent(metaclass=MumpyEnum):
    CONNECTED = 'self_connected'
    DISCONNECTED = 'self_disconnected'
    UDP_CONNECTED = 'udp_connected'
    UDP_DISCONNECTED = 'udp_disconnected'
    CHANNEL_ADDED = 'channel_added'
    CHANNEL_UPDATED = 'channel_updated'
    CHANNEL_REMOVED = 'channel_removed'
    USER_CONNECTED = 'user_connected'
    USER_DISCONNECTED = 'user_disconnected'
    USER_KICKED = 'user_kicked'
    USER_BANNED = 'user_banned'
    USER_STATS_UPDATED = 'user_stats_updated'
    USER_REGISTERED = 'user_registered'
    USER_COMMENT_UPDATED = 'user_comment_updated'
    USER_AVATAR_UPDATED = 'user_avatar_updated'
    USER_SELF_MUTED = 'user_self_muted'
    USER_SELF_DEAFENED = 'user_self_deafened'
    USER_SELF_UNMUTED = 'user_self_unmuted'
    USER_SELF_UNDEAFENED = 'user_self_undeafened'
    USER_MUTED = 'user_muted'
    USER_DEAFENED = 'user_deafened'
    USER_UNMUTED = 'user_unmuted'
    USER_UNDEAFENED = 'user_undeafened'
    USER_RECORDING = 'user_recording'
    USER_STOPPED_RECORDING = 'user_stopped_recording'
    MESSAGE_RECEIVED = 'message_received'
    MESSAGE_SENT = 'message_sent'
    BANLIST_MODIFIED = 'banlist_modified'
    AUDIO_TRANSMISSION_RECEIVED = 'audio_transmission_received'
    AUDIO_TRANSMISSION_SENT = 'audio_transmission_sent'
    AUDIO_DISABLED = 'audio_disabled'
    AUDIO_ENABLED = 'audio_enabled'


PROTOCOL_VERSION = (1, 2, 19)  # (major, minor, patch)
RELEASE_STRING = "MumPy 1.0b"
OS_STRING = RELEASE_STRING
OS_VERSION_STRING = "Python %s - %s %s" % (PYTHON_VERSION, platform.system(), platform.release())

PING_INTERVAL = 10  # seconds
