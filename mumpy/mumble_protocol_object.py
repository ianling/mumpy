import weakref


class MumbleProtocolObject:
    def __init__(self, server, message):
        # keep a weak reference to the parent object (the Mumpy instance)
        self._server = weakref.proxy(server)
        self.update(message)

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
        print(message)  # for debugging
        updated_fields = message.ListFields()
        if prefix is None:
            object_to_update = self
        else:
            object_to_update = getattr(self, prefix)
        for field, value in updated_fields:
            setattr(object_to_update, field.name, value)
