Usage
=====

Mumpy is both a fully-featured Mumble client and a server.
As a client, it offers both an API for interacting with a Mumble server
and an event-driven framework for reacting to various actions and situations as they occur.

This same API is offered from the server's perspective as well, and is also event-driven. This gives you full control
over how the server behaves in any situation, and allows you to easily expand functionality beyond what is offered by the official
Mumble server.

The API contains all the features you would expect from Mumble,
such as the ability to send and receive voice and text chat messages, kick/ban/mute/deafen users,
create/edit/remove channels, and most everything else you can do in the official Mumble client and server.

.. code:: python

    import mumpy

    client = mumpy.Client()
    client.connect('localhost', port=64738)
    client.text_message("I am sending a text chat message to my current channel.")
    client.kick_user("BadUser1337", reason="Not good.")

    # you can also interact with User and Channel objects in intuitive ways
    bad_user = client.get_user('BadUser1337')
    bad_user.kick(ban=True)

    my_current_channel = client.channel
    my_current_channel.rename('New Channel Name')

A full list of all the methods available can be found in the :ref:`api_reference` section of the documentation.

The event-driven portion is essentially an alert system that allows you to run your own code in response to
specific events happening. Some of these events include users connecting or disconnecting,
people sending voice or text chat messages, people being kicked or banned, and new channels being created or removed.

A full list of all the events you can add handlers for can be found in the :class:`.EventType`
part of the :ref:`api_reference` section.

Event handlers should always accept one parameter, an :class:`.Event` object.
This object will contain a number of attributes that provide more information about the event that occurred, such as:

* ``.type`` - the type of event, from the :class:`.EventType` enum
* ``.server`` - the :class:`.Client` instance that the event originated from
* ``.raw_message`` - the raw protobuf message object that caused the event to fire.
                     The fields you can expect to see in each protobuf message type are
                     documented in the `official Mumble client's protobuf definition file`_

Example event handler for the :obj:`.USER_KICKED` event.

.. code:: python

    def kick_event_handler(event):
        kicker = event.server.get_user(raw_message.actor)
        victim = event.server.get_user(raw_message.session)
        print(f"{kicker.name} kicked {victim.name} from the server!")

    my_client.add_event_handler(EventType.USER_KICKED, kick_event_handler)

Many parts of Mumpy operate asynchronously, so some of the functions do not return values themselves.
For example, when you call the :py:meth:`.Client.update_user_stats` method,
a request for the user's stats is sent to the server. The server will eventually
(usually within milliseconds) respond, which will trigger the
:obj:`.USER_STATS_UPDATED` event,
where you can handle the values that the server sent back to us.

A (non-exhaustive) list of events that each function is expected to cause is included
in each function's documentation in the :ref:`api_reference` section.
If you would like a log all the events Mumpy is firing in real time,
enable DEBUG logging output. See the :ref:`logging` section below for more details.

SSL Certificates
----------------

Mumble allows clients to use an SSL certificate to verify their identity on the server.
This also allows the server to remember which channel they were last in when they disconnected,
and assign them various permissions on the server.

You can generate a self-signed SSL certificate and key file using a command like the following:

.. code:: bash

    $ openssl req -newkey rsa:2048 -nodes -keyout mumpy_key.pem -x509 -days 2000 -out mumpy_certificate.pem

To use the certificate and key file you generated, use the ``certfile`` and ``keyfile`` parameters
when connecting to a server:

.. code:: python

    import mumpy
    my_client = mumpy.Client()
    my_client.connect('localhost', certfile='mumpy_certificate.pem', keyfile='mumpy_key.pem')

Likewise, the server portion of Mumpy must provide a certificate identifying itself to clients when they connect.

.. code:: python

    import mumpy
    my_server = mumpy.Server('server_certificate.pem', 'server_key.pem')

.. _logging:

Logging
-------

Mumpy uses Python's logging library to handle logging. If you are seeing too many logs,
you can add the following code to your program to reduce the logging verbosity:

.. code:: python

    import logging

    logging.basicConfig(level=logging.WARNING)  # DEBUG, INFO, and ERROR are also valid

.. _official Mumble client's protobuf definition file: https://github.com/mumble-voip/mumble/blob/master/src/Mumble.proto