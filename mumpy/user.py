class User(dict):
    def __init__(self, message):
        self.audio_log = []
        self.audio_buffer = b''
        self.audio_buffer_dict = {}
        self.channel_id = 0
        self.stats = {}
        self.update(message)

    def __getattr__(self, attr):
        return self[attr]

    def __setattr__(self, attr, value):
        self[attr] = value

    @property
    def session_id(self):
        return self.session

    # uses a protobuf message to update the object's fields
    def update(self, message, prefix=None):
        updated_fields = message.ListFields()
        for field, value in updated_fields:
            if prefix is None:
                self[field.name] = value
            else:
                self[prefix][field.name] = value
