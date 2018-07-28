class User(dict):
    def __init__(self, message):
        self.audio_log = []
        self.audio_buffer = b''
        self.channel_id = 0
        self.update(message)

    def __getattr__(self, attr):
        return self[attr]

    def __setattr__(self, attr, value):
        self[attr] = value

    # uses a protobuf message to update the object's fields
    def update(self, message):
        updated_fields = message.ListFields()
        for field, value in updated_fields:
            self[field.name] = value
