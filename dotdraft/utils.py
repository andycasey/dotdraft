
import os
from random import choice
from string import (ascii_uppercase, digits)


def random_string(N=10):
    """ Return a random string of alphanumeric characters of length `N`. """
    return ''.join(choice(ascii_uppercase + digits) for _ in range(N))



def get_unused_filename(folder, suffix=None, N=10):
    """
    Get a temporary filename.

    :param folder:
        The folder.

    :param suffix: [optional]
        An optional suffix to add to the filename.

    :param N: [optional]
        Length of the basename (ignoring the suffix).

    :returns:
        The full path name.
    """

    suffix = suffix or ""

    basename = "".join([random_string(N=N), suffix])
    while os.path.exists(os.path.join(folder, basename)):
        basename = "".join([random_string(N=N), suffix])

    return os.path.join(folder, basename)


# General utilities.
class Alarm(Exception):
    pass

def alarm_handler(signum, frame):
    raise Alarm
