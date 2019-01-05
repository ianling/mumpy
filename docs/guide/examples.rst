Examples
========

Barebones Connection
--------------------

This example simply connects to a server, sends a text chat message to the channel, and then disconnects.

.. code:: python

    from mumpy import Mumpy

    my_bot = Mumpy(username="MyBot")
    my_bot.connect('localhost')  # port=64738 by default
    my_bot.text_message("HELLO!")
    my_bot.disconnect()

Barebones Connection Using 'with'
---------------------------------

This example uses a different syntax to perform all the same actions as the example above.

.. code:: python

    from mumpy import Mumpy

    with Mumpy() as my_bot:
        my_bot.connect('localhost')
        my_bot.text_message("Hello!")

Echo Bot
--------

This example is a bot that echoes all text chat messages back to the original sender as a private message.

.. code:: python

    from mumpy import Mumpy, MumpyEvent
    from time import sleep

    def text_message_handler(mumpy_instance, raw_message):
        sender = mumpy_instance.get_user_by_id(raw_message.actor)
        message_body = raw_message.message
        mumpy_instance.text_message(message_body, users=(sender,))

    my_bot = Mumpy(username="MyBot")
    my_bot.add_event_handler(MumpyEvent.MESSAGE_RECEIVED, text_message_handler)  # add our function as a handler for MESSAGE_RECEIVED events
    my_bot.connect('localhost')

    while my_bot.is_alive():
        sleep(1)

Play WAV File
-------------

This example is a bot that connects to a server, waits for the UDP socket to become established, and then immediately transmits a WAV file. At the moment, WAV files must be in 48kHz 16-bit format.

.. code:: python

    from mumpy import Mumpy, MumpyEvent
    from time import sleep

    def udp_connected_handler(mumpy_instance, raw_message):
        mumpy_instance.play_wav('/home/ian/some_sound.wav')

    my_bot = Mumpy(username="MyBot")
    my_bot.add_event_handler(MumpyEvent.UDP_CONNECTED, udp_connected_handler)
    my_bot.connect('localhost')

    while my_bot.is_alive():
        sleep(1)