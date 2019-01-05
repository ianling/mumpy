Usage
=====

Mumpy is a fully-featured Mumble client that offers both an API for interacting with a Mumble server, and an event-driven framework for reacting to various actions and situations as they occur.

The API portion contains all the features you would expect from a Mumble client, such as the ability to send and receive voice and text chat messages, kick/ban/mute/deafen users, create/edit/remove channels, and most everything else you can do in the official Mumble client.

.. code:: python

    my_mumpy.text_message("I am sending a text chat message to my current channel.")
    my_mumpy.kick_user_by_name("BadUser1337", reason="Not good.")
    my_channel = my_mumpy.get_current_channel()
    my_channel.rename('New Channel Name')
    bad_user = my_mumpy.get_user_by_name('BadUser1337')
    bad_user.kick(ban=True)

A full list of all the methods available can be found in the :ref:`api_reference` section of the documentation.

The event-driven portion is essentially an alert system that allows you to run your own code in response to specific events happening. Some of these events include users connecting/disconnecting to/from the server, people sending voice and text chat messages, people being kicked or banned, new channels being created, and a variety of others.

Event handlers should always accept two parameters; the first parameter is the :class:`~mumpy.mumpy.Mumpy` instance that the event originated from, and the second is the protobuf message object that caused the event to fire. The fields you can expect to see in each protobuf message type are documented in the `official Mumble client's protobuf definition file`_.

.. code:: python

    def kick_event_handler(mumpy_instance, raw_message):
        kicker = mumpy_instance.get_user_by_id(raw_message.actor)
        victim = mumpy_instance.get_user_by_id(raw_message.session)
        print(f"{kicker.name} kicked {victim.name} from the server!")

    my_mumpy.add_event_handler(MumpyEvent.USER_KICKED, kick_event_handler)

A full list of all the events you can add handlers for can be found in the :class:`~mumpy.constants.MumpyEvent` part of the :ref:`api_reference` section.


.. _official Mumble client's protobuf definition file: https://github.com/mumble-voip/mumble/blob/master/src/Mumble.proto