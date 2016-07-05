import logging
import sys
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

from dotdraft import Revision
import hooks as integration
import utils