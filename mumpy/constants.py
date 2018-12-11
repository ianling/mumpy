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
    CHANNEL_REMOVED = 'channel_removed'
    USER_CONNECTED = 'user_connected'
    USER_DISCONNECTED = 'user_disconnected'
    USER_KICKED = 'user_kicked'
    USER_BANNED = 'user_banned'
    USER_STATS_UPDATED = 'user_stats_updated'
    MESSAGE_RECEIVED = 'message_received'
    MESSAGE_SENT = 'message_sent'
    BANLIST_MODIFIED = 'banlist_modified'
    AUDIO_TRANSMISSION_RECEIVED = 'audio_transmission_received'
    AUDIO_TRANSMISSION_SENT = 'audio_transmission_sent'


PROTOCOL_VERSION = (1, 2, 19)  # (major, minor, patch)
RELEASE_STRING = "MumPy 1.0b"
OS_STRING = RELEASE_STRING
OS_VERSION_STRING = "Python %s - %s %s" % (PYTHON_VERSION, platform.system(), platform.release())

PING_INTERVAL = 10  # seconds
