import pyda_core
from .process import Process

def process():
    # todo: remove the bogus argument
    return Process(pyda_core.process(""))
