Examples
========

Barebones Connection
--------------------

This example simply connects to a server and sends a text chat message.

    from mumpy import Mumpy

    my_bot = Mumpy(username="MyBot")
    my_bot.connect('localhost')  # port=64738 by default
    my_bot.text_message("HELLO, EVERYONE.")

Echo Bot
--------

This example echoes all text chat messages back to the original sender.

    from mumpy import Mumpy, MumpyEvent
    from time import sleep

    def connected_event_handler(bot, raw_message):
        bot.text_message("Hello everyone, I just connected. My name is {0}.".format(bot.username))
        sleep(5)
        bot.text_message("I am leaving now, goodbye.")
        bot.disconnect()

    my_bot = Mumpy(username="MyBot")
    my_bot.add_event_handler(MumpyEvent.CONNECTED, connected_event_handler)
    my_bot.connect('localhost')  # port=64738 by default

    while my_bot.is_alive():
        sleep(3)

    print("The bot has died!")