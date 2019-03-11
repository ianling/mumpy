from mumpy.mumble_protocol_object import MumbleProtocolObject


class User(MumbleProtocolObject):
    def __init__(self, server, message):
        self.audio_log = []
        self.audio_buffer = b''
        self.audio_buffer_dict = {}
        self.channel_id = 0
        self.stats = MumbleProtocolObject(server)
        super().__init__(server, message)

    @property
    def session_id(self):
        """
        This user's session ID.

        Returns:
            int: session ID
        """
        return self.session

    @property
    def channel(self):
        """
        This user's current channel.

        Returns:
            Channel: the user's current channel
        """
        return self._server.get_channel(self.channel_id)

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

    def clear_audio_log(self):
        """
        Clears this user's audio log, removing all their completed audio transmissions from memory.

        Returns:
            None
        """
        self.audio_log = []

    def kick(self, reason="", ban=False):
        """
        Kicks user. Bans the user if ban is True.

        Args:
            reason(str): The reason for kicking
            ban(bool): Whether or not the user should also be banned

        Returns:
            None
        """
        self._server.kick_user(self, reason, ban)

    def mute(self):
        """
        Mutes the user.

        Returns:
            None
        """
        self._server.mute_user(self)

    def deafen(self):
        """
        Deafens the user.

        Returns:
            None
        """
        self._server.deafen_user(self)

    def unmute(self):
        """
        Unmutes the user.

        Returns:
            None
        """
        self._server.unmute_user(self)

    def undeafen(self):
        """
        Undeafens the user.

        Returns:
            None
        """
        self._server.undeafen_user(self)

    def move_to_channel(self, channel):
        """
        Moves the user to the specified channel.

        Args:
            channel(Channel): the Channel to move them to

        Returns:
            None
        """
        self._server.move_user_to_channel(self, channel)

    def register(self):
        """
        Registers the user on the server.

        Returns:
            None
        """
        self._server.register_user(self)

    def unregister(self):
        """
        Unregisters the user on the server.

        Returns:
            None
        """
        self._server.unregister_user(self)

    def update_stats(self):
        """
        Requests updated stats about the user from the server.

        Returns:
            None
        """
        self._server.update_user_stats(self)
