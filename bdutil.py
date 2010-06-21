"""
Some util classes
"""

def abstract():
    """
    Abstract class implementation helper.

    Taken from http://norvig.com/python-iaq.html
    """
    import inspect
    caller = inspect.getouterframes(inspect.currentframe())[1][3]
    raise NotImplementedError(caller + ' must be implemented in subclass')



class Colors:
    """
    Terminal foreground colors
    """
    Red     = "\033[31m"
    Green   = "\033[32m"
    Yellow  = "\033[33m"
    Blue    = "\033[34m"
    Magenta = "\033[35m"
    Cyan    = "\033[36m"
    Black   = "\033[37m"
    Reset   = "\033[0m"

    def __init__(self):
        pass
