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

    def rename(self, new_name):
        """
        Sets the channel's name to new_name.

        Args:
            new_name(str): The new name for the channel

        Returns:
            None
        """
        self._server.rename_channel(self, new_name)

    def remove(self):
        """
        Removes this channel from the server.

        Returns:
            None
        """
        self._server.remove_channel(self)

    def text_message(self, message):
        """
        Sends a text message to this channel.

        Args:
            message(str): the message

        Returns:
            None
        """
        self._server.text_message(message, channels=(self,))
