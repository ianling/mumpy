Examples
========

Barebones Connection
--------------------

This example simply connects to a server, sends a text chat message to the channel, and then disconnects.

.. codeblock:: python

    from mumpy import Mumpy

    my_bot = Mumpy(username="MyBot")
    my_bot.connect('localhost')  # port=64738 by default
    my_bot.text_message("HELLO!")
    my_bot.disconnect()

Barebones Connection using 'with'
---------------------------------

This example uses a different syntax to perform all the same actions as the example above.

.. codeblock:: python

    from mumpy import Mumpy

    with Mumpy() as my_bot:
        my_bot.connect('localhost')
        my_bot.text_message("Hello!")

Echo Bot
--------

This example is a bot that echoes all text chat messages back to the original sender.

.. codeblock:: python

    from mumpy import Mumpy, MumpyEvent
    from time import sleep

    def text_message_handler(bot, raw_message):
        sender = bot.get_user_by_id(raw_message.actor)
        message_body = raw_message.message
        bot.text_message(message_body, users=(sender,))

    my_bot = Mumpy(username="MyBot")
    my_bot.add_event_handler(MumpyEvent.MESSAGE_RECEIVED, text_message_handler)  # add our function as a handler for MESSAGE_RECEIVED events
    my_bot.connect('localhost')

    while my_bot.is_alive():
        sleep(1)