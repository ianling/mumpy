class EventHandler(list):
    """
    A list of functions that will be called when the relevant event is fired.

    Example:

    event_handler = EventHandler()
    event_handler.append(myFunctionThatHandlesEvents)
    event_handler.append(myOtherFunctionThatHandlesEvents)

    if event == MY_EVENT:
        event_handler()  # this calls all of the functions that have been added to event_handler

    """
    def __call__(self, *args, **kwargs):
        for function_handle in self:
            function_handle(*args, **kwargs)

    def __repr__(self):
        return "EventHandler({})".format(list.__repr__(self))
