from mumpy.mumble_protocol_object import MumbleProtocolObject


class Event(MumbleProtocolObject):
    def __init__(self, server, message):
        self.type = None
        self.raw

    def __str__(self):
        return self.type

    @property
    def session_id(self):
        """
        This user's session ID.

        Returns:
            int: session ID
        """
        return self.session
