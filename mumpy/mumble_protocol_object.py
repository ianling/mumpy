import weakref


class MumbleProtocolObject(dict):
    def __init__(self, server, message):
        self._server = weakref.proxy(server)
        self.update(message)

    def __getattr__(self, attr):
        try:
            return self[attr]
        except KeyError:
            return None

    def __setattr__(self, attr, value):
        self[attr] = value

    def update(self, message, prefix=None):
        """
        Uses a protobuf message to update the object's fields.
        
        Example: <obj>.update(message, prefix="stats") will store all the fields in message at <obj>.stats.*

        Args:
          message(protobuf message): the protobuf message to use when updating this object's values
          prefix(str): top-level attribute to store the fields in (Default value = None)

        Returns:
            None
        """
        print(message)
        updated_fields = message.ListFields()
        for field, value in updated_fields:
            if prefix is None:
                self[field.name] = value
            else:
                self[prefix][field.name] = value
