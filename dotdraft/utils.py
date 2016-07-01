
from random import choice
from string import (ascii_uppercase, digits)


def random_string(N=10):
    """ Return a random string of alphanumeric characters of length `N`. """
    return ''.join(choice(ascii_uppercase + digits) for _ in range(N))
