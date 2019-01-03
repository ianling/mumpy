# Mumpy [![Docs](https://readthedocs.org/projects/mumpy/badge/?version=latest)](https://mumpy.readthedocs.io/)

Mumpy is a Mumble client framework written in Python 3.

It is event-driven, making it perfect for writing Mumble bots.

## Requirements

* Python 3.6+
    * opuslib
    * pycryptodome
    * protobuf
* libopus (for audio)
    * Debian/Ubuntu: `apt install libopus0`
    * OSX: `brew install opus`
    * Windows: http://opus-codec.org/downloads/

## Documentation

Examples, API docs, and other documentation are all available over on [ReadTheDocs](https://mumpy.readthedocs.io/).

Below is some basic code to get you started. It creates a bot and adds a function to handle CONNECTED events. This event handler function sends a text message to everyone in the bot's current channel, then disconnects from the server after 5 seconds. Once the bot has disconnected, execution ends.

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
        print("The bot is still alive.")
        sleep(3)
    
    print("The bot has died!")

## To-do (in order of priority)

* Add remaining client protobuf message types (including ContextActionModify and ContextAction)
* Allow sending other audio besides 48KHz 16-bit WAV/PCM
* Add per-user audio storage limits
* Mixdown audio
* A better way to store audio than a list of potentially massive byte strings on each user
* Add function to manually kill UDP connection and switch back to TCP
