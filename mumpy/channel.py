from mumpy.mumble_protocol_object import MumbleProtocolObject


class Channel(MumbleProtocolObject):
    @property
    def id(self):
        return self.channel_id

    def update_description(self):
        self._server.request_blob(channel_descriptions=[self.id])

    def get_users(self):
        users = self._server.get_users()
        return [user for user in users.values() if user.channel_id == self.id]
