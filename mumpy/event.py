from mumpy.mumble_protocol_object import MumbleProtocolObject
from time import time


class Event(MumbleProtocolObject):
    def __init__(self, server, event_type, message=None):
        self.type = event_type
        self.raw_message = message
        self.timestamp = time()
        super().__init__(server)

    def __str__(self):
        return self.type
