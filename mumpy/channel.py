from mumpy.mumble_protocol_object import MumbleProtocolObject


class Channel(MumbleProtocolObject):
    @property
    def id(self):
        """
        This channel's ID.
        """
        return self.channel_id

    def get_description(self):
        """
        Queries the server for the channel's description.

        Returns:
            None
        """
        self._server.request_blob(channel_descriptions=[self.id])

    def get_users(self):
        """
        Retrieves a list of Users in this channel.

        Returns:
            list: a list of the Users in this channel
        """
        users = self._server.get_users()
        return [user for user in users.values() if user.channel_id == self.id]
