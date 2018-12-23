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
        """
        This user's session ID.
        """
        return self.session

    @property
    def user_id(self):
        """
        This user's user ID.
        """
        return self.user_id

    def update_texture(self):
        """
        Query the server for this user's texture.

        Returns:
            None
        """
        self._server.request_blob(user_textures=[self.session_id])

    def update_comment(self):
        """
        Query the server for this user's comment.

        Returns:
            None
        """
        self._server.request_blob(user_comments=[self.session_id])

    def get_channel(self):
        """
        Get this user's current Channel.

        Returns:
            Channel: the user's current Channel
        """
        return self._server.get_channel_by_id(self.channel_id)

    def clear_audio_log(self):
        """
        Clears this user's audio log, removing all their completed audio transmissions from memory.

        Returns:
            None
        """
        self.audio_log = []
