from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64
import time
from threading import Thread

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

def thread():
    print("thread start")
    time.sleep(1)
    print("thread end")

t = Thread(target=thread)
t.start()

time.sleep(3)
p.run()
time.sleep(3)
print("pass")
