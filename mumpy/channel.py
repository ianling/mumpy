from mumpy.mumble_protocol_object import MumbleProtocolObject


class Channel(MumbleProtocolObject):
    @property
    def id(self):
        return self.channel_id
