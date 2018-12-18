from mumpy.mumble_protocol_object import MumbleProtocolObject


class User(MumbleProtocolObject):
    def __init__(self, server, message):
        self.audio_log = []
        self.audio_buffer = b''
        self.audio_buffer_dict = {}
        self.channel_id = 0
        self.stats = {}
        super().__init__(server, message)

    @property
    def session_id(self):
        return self.session
