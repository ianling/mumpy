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

    def update_texture(self):
        self._server.request_blob(user_textures=[self.session_id])

    def update_comment(self):
        self._server.request_blob(user_comments=[self.session_id])

    def get_channel(self):
        return self._server.get_channel_by_id(self.channel_id)

    def clear_audio_log(self):
        self.audio_log = []