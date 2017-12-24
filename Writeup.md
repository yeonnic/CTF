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



