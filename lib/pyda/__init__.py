import sys, os
try:
    from .base import *
except ImportError:
    # Pyda will not import correctly if not run via the DynamoRIO tool
    sys.stderr.write("[Pyda] You must use the `pyda` script to use pyda. You cannot import pyda directly.\n")
    pass

sys.path.append(os.path.join(os.path.dirname(__file__), 'hacks'))
