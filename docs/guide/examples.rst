Client Examples
===============

Barebones Connection
--------------------

This example simply connects to a server, sends a text chat message to the channel, and then disconnects.

.. code:: python

    import mumpy

    my_bot = mumpy.Client(username="MyBot")
    my_bot.connect('localhost')  # port=64738 by default
    my_bot.text_message("HELLO!")
    my_bot.disconnect()

Barebones Connection Using 'with'
---------------------------------

This example uses a different syntax to perform all the same actions as the example above.

.. code:: python

    import mumpy

    with mumpy.Client() as my_bot:
        my_bot.connect('localhost')
        my_bot.text_message("Hello!")

Echo Bot
--------

This example is a bot that echoes all text chat messages back to the original sender as a private message.

.. code:: python

    import mumpy
    from time import sleep

    def text_message_handler(event):
        sender = event.server.get_user_by_id(raw_message.actor)
        message_body = event.raw_message.message
        sender.text_message(message_body)

    my_bot = mumpy.Client(username="MyBot")
    my_bot.add_event_handler(mumpy.EventType.MESSAGE_RECEIVED, text_message_handler)  # add our function as a handler for MESSAGE_RECEIVED events
    my_bot.connect('localhost')

    while my_bot.is_alive():
        sleep(1)

Play WAV File
-------------

This example is a bot that connects to a server, waits for the UDP socket to become established, and then immediately transmits a WAV file
using the ``udp_connected_handler`` function. At the moment, WAV files must be in 48kHz 16-bit format.

.. code:: python

    import mumpy
    from time import sleep

    def udp_connected_handler(event):
        event.server.play_wav('/home/ian/some_sound.wav')

    my_bot = mumpy.Client(username="MyBot")
    my_bot.add_event_handler(mumpy.EventType.UDP_CONNECTED, udp_connected_handler)
    my_bot.connect('localhost')

    while my_bot.is_alive():
        sleep(1)

Server Examples
===============

Coming soon...