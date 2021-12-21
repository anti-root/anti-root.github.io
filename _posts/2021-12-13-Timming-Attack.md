---
title:  "Timing Attack - Part"
excerpt: "mathn3wb13"

categories:
  - Research
tags:
  - Crypto
  - System
  - mathn3wb13
  
date: 2021-12-13 12:00:00 +0900
last_modified_at: 2021-12-13 12:00:00 +0900

---

# Timing Attack - Part

분야: 시스템, 암호학
업로드 여부: No
열: 2021년 12월 13일
작성자: 익명

## Timing Attack

 말 그대로 암호화 계산 시간을 분석해서 키를 유추하는 방법이다. 암호모듈의 루틴에 따른 시간의 정보가 외부로 새어 나가면 이 취약점이 발생해서 공격자가 키를 탈취할 수 있게 된다.

 최근 들어서 관심이 생긴 것은 부채널 공격, 그 중   OTP에서 발생하는 Timing Attack에 대해 알아보는 시간을 가졌다. 이번 2주 동안 다 하기엔 대충 훑고 넘어가기엔 아까울 정도로 자료가 많길래 몇 차시 나눠서 쭉 이어서 이 주제로 공부를 하게 될 것 같다.

 각 종류별로 개념부터 익히고 시작하는 방식으로 진행 될 예정이다. 

이번 차시는 가장 널리 알려진, CTF에서도 몇 번 출제된 적이 있는 대표적인 케이스 대해 설명한다.

## Timing Attack - OTP

만약에 OTP 암호화를 진행하고 검증하는 루틴이 다음과 같으면 어떻게 될까?

```python
for c, i in zip(ciphertext, plaintext):
	if c != (i^key): return False
```

당연히 중간 중간 time값이 튀는 경우에 대해서 올바른 key를 찾았음을 유추해낼 수 있다.

예를 들어, 아래와 같은 코드가 있다고 치자 

key는 /dev/urandom값을 읽어온 임의의 난수 바이트열이다. 이해를 돕기 위해 코드에서는 상수로 넣음

```cpp
#include <stdio.h>

int checkPassword(char * password, char * ciphertext, char * secret_message)
{
    for(size_t i = 0; i < 0x10; ++i)
    {
        if (secret_message[i] != (ciphertext[i] ^ password[i]))
            return 0;
    }
    return 1;
}

char* encryption(char * key, char * secret_message)
{
    static char ciphertext[0x10];
    for (size_t i = 0; i < 0x10; ++i)
    {
        ciphertext[i] = secret_message[i] ^ key[i];
    }
    
    return ciphertext;
}

int main()
{
    char secret_message[] = "Secret Message!";
    char buf[0x10] = {0,};
    char key[0x10] = {46, 37, 55, 51, 67, 32, 42, 78, 70, 51, 53, 74, 74, 51, 79, 54};
    char* ciphertext = encryption(key, secret_message);
    printf("Encrypted Message: ");
    for (size_t i = 0; i < 0x10; ++i)
    {
        printf("%x ", ciphertext[i]);
    }
    printf("\n");
    printf("Input your password >>> ");
    fgets(buf, 16, stdin);
    if(!checkPassword(buf, ciphertext, secret_message))
    {
        printf("Invalid Password \n");
    }
    else printf("Password OK! \n");

    return 0;
}
```

생성된 OTP에 대해 한 바이트씩 비교하고 중간에 잘못된 OTP가 있으면 멈춘다. 다르게 생각하면, 한 바이트에 대해 time이 길어지는 값을 찾으면, 다음 반복문으로 넘어갔다는 얘기가 되므로 올바른 값을 찾게 됐다는 의미이다. 직관적이고 쉬운 취약점이지만, 실제 발생 사례가 있는 취약점이다.

[https://hackerone.com/reports/277534](https://hackerone.com/reports/277534)

## 다음 차시 TODO

ECDSA Timing attack 공부