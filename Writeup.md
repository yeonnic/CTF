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
