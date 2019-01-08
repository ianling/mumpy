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

Because this is largely an asynchronous framework, many of the functions do not return values themselves. For example, when you call the :py:meth:`~mumpy.mumpy.Mumpy.update_user_stats` method, a request for the user's stats is sent to the server. The server will eventually (usually within milliseconds) respond, which will trigger the :py:const:`~mumpy.constants.MumpyEvent.USER_STATS_UPDATED` event, where you can handle the values that the server sent back to us.

SSL Certificates
----------------

Mumble allows you to use an SSL certificate as the client in order to verify your identity on the server. This also allows the server to remember which channel you were last in when you disconnected, and assign you administrator privileges.

You can generate a self-signed SSL certificate and key file using a command like the following:

.. code:: bash

    $ openssl req -newkey rsa:2048 -nodes -keyout mumpy_key.pem -x509 -days 2000 -out mumpy_certificate.pem

To use the certificate and key file you generated, use the ``certfile`` and ``keyfile`` parameters when connecting to a server:

.. code:: python

    my_mumpy = Mumpy()
    my_mumpy.connect('localhost', certfile='mumpy_certificate.pem', keyfile='mumpy_key.pem')

Logging
-------

Mumpy uses Python's logging library to handle logging. If you are seeing too many logs, you can add the following code to your program to reduce the logging verbosity:

.. code:: python

    import logging

    logging.basicConfig(level=logging.INFO)  # you can also use WARNING or ERROR

.. _official Mumble client's protobuf definition file: https://github.com/mumble-voip/mumble/blob/master/src/Mumble.proto