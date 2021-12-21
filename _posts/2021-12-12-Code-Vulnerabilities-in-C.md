---
title:  "Code Vulnerabilities in C"
excerpt: "SH1R0_0"

categories:
  - Research
tags:
  - System
  - SH1R0_0
  
date: 2021-12-12 12:00:00 +0900
last_modified_at: 2021-12-12 12:00:00 +0900

---

# 001. 스택 버퍼 오버플로우 (Stack Buffer Overflow)

### Example 1

```c
// stack-1.c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char buf[16];
    gets(buf);

    printf("%s", buf);
}
```

위 코드를 볼 때 gets() 함수에 **별도의 길이 제한이 없기 때문에** 16바이트를 넘는 데이터를 입력한다면 스택 버퍼 오버플로우가 발생합니다.

![https://blog.kakaocdn.net/dn/Ocfnt/btqVJSeijq5/WeZVrkpppko9OzYKekAkt1/img.png](https://blog.kakaocdn.net/dn/Ocfnt/btqVJSeijq5/WeZVrkpppko9OzYKekAkt1/img.png)

버퍼에 16byte만큼 A를 입력하고 추가로 BBBBCCCC를 입력하자, SFP가 0x42424242로, RET가 0x43434343로 바뀐 모습을 볼 수 있습니다. 이와 같이 스택 버퍼 오버플로우는 프로그램이 스택에 위치한 버퍼에 할당된 것보다 더 많은 데이터를 쓸 때 발생합니다. 버퍼 오버 플로우 취약점은 길이 제한이 없는 API 함수들을 사용하거나 버퍼의 크기보다 입력받는 데이터의 길이가 더 크게 될 때 일어납니다.

### Example 2

```c
// stack-2.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_auth(char *password) {
    int auth = 0;
    char temp[16];

    strncpy(temp, password, strlen(password));

    if(!strcmp(temp, "SECRET_PASSWORD"))
        auth = 1;

    return auth;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: ./stack-1 ADMIN_PASSWORD\n");
        exit(-1);
    }

    if (check_auth(argv[1]))
        printf("Hello Admin!\n");
    else
        printf("Access Denied!\n");
}
```

먼저 main 함수 코드부터 살펴봅니다.

![https://blog.kakaocdn.net/dn/bgiaLY/btqVJSZHlUO/hQ3rP4E44tLq1OXT29rwzK/img.png](https://blog.kakaocdn.net/dn/bgiaLY/btqVJSZHlUO/hQ3rP4E44tLq1OXT29rwzK/img.png)

argc가 2가 아니면 Usage: ./stack-1 ADMIN_PASSWORD 를 출력하고 종료합니다. check_auth() 함수로 사용자가 ADMIN_PASSWORD에 입력한 argv[1] 값을 인자로 넘겨줍니다. 이때 check_auth(argv[1])값이 참이면 Hello Admin! 을 출력하고 값이 거짓이면 Access Denied! 를 출력합니다. 다음은 check_auth 함수입니다.

![https://blog.kakaocdn.net/dn/qLHG4/btqVCc5Z0sD/6UOEH8GjiB8BQOfndzwk21/img.png](https://blog.kakaocdn.net/dn/qLHG4/btqVCc5Z0sD/6UOEH8GjiB8BQOfndzwk21/img.png)

argv[1] 값을 char *password를 통해서 받아옵니다. strncpy 함수를 이용해 temp[16]에 password값을 password길이만큼 복사합니다. 그래서 인자로 TEST라는 값을 넘겨주면 temp에 "TEST" 가 복사되게 됩니다. 그 후 strcmp 함수를 이용해 temp와 "SECRET_PASSWORD" 값을 비교합니다. 두 값이 같다면 0을 반환하기 때문에 strcmp 앞에 ! 를 붙여서 0이 나오면 TRUE로 변경되도록 합니다. 그 후 auth에 1을 대입합니다. 이후 auth값을 반환합니다. 아래는 인자에 TEST 값을 넘겨주었을 때 결과입니다.

![https://blog.kakaocdn.net/dn/bcAkM1/btqVJRmbVzc/VkXNDClL5fCzzzwVjfZ8A0/img.png](https://blog.kakaocdn.net/dn/bcAkM1/btqVJRmbVzc/VkXNDClL5fCzzzwVjfZ8A0/img.png)

이때는 당연히 "TEST"는 "SECRET_PASSWORD"와 다르기 때문에 auth값이 0으로 변동이 없고 Access Denied! 를 출력합니다. 그럼 이번에 SECRET_PASSWORD 를 입력하면 어떨까요?

![https://blog.kakaocdn.net/dn/bo91S1/btqVIKt7oYx/hdEvK1zimnX4ilKjEQ32sK/img.png](https://blog.kakaocdn.net/dn/bo91S1/btqVIKt7oYx/hdEvK1zimnX4ilKjEQ32sK/img.png)

Hello Admin! 문구가 출력됩니다. password는 길이제한이 따로 없고 사용자가 입력한대로 문자를 복사하므로 temp 크기인 16byte보다 더 많은 문자를 입력하여 auth 부분(4byte)만큼 을 덮어 버리면 auth가 TRUE로 되면서 check_auth 함수에서 반환하게 됩니다.

![https://blog.kakaocdn.net/dn/9gZXD/btqVzRBijr7/HhJKip2CZhYyUrI7ZepZhK/img.png](https://blog.kakaocdn.net/dn/9gZXD/btqVzRBijr7/HhJKip2CZhYyUrI7ZepZhK/img.png)

이렇게 패스워드를 입력하지 않아도 Hello Admin! 이 출력되는걸 확인할 수 있습니다. 여기서 더 많은 문장을 입력하게 되면 RET 값을 변경하면 시스템의 권한을 장악하는 등 더 많은 작업을 할 수 있습니다.

![https://blog.kakaocdn.net/dn/b4xTwe/btqVzR2pDnk/cdo2xUG72kgIzKOrmETcDk/img.png](https://blog.kakaocdn.net/dn/b4xTwe/btqVzR2pDnk/cdo2xUG72kgIzKOrmETcDk/img.png)

### Example 3

```c
// stack-3.c
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char win[4];
    int size;
    char buf[24];

    scanf("%d", &size);
    read(0, buf, size);
    if (!strncmp(win, "ABCD", 4)){
        printf("Theori{-----------redacted---------}");
    }
}
```

scanf로 값을 입력받아 size에 저장하고 read 함수를 이용해 size만큼 buf 데이터를 입력받습니다. (0번 파일 디스크립터는 표준입력입니다.) win이 "ABCD"면 Theori{-----------redacted---------} 를 출력하나 봅니다. redacted 부분을 보기위해선 버퍼오버플로우(BOF) 공격을 해서 win 값을 "ABCD"로 바꿔야 할 것 같습니다.

![https://blog.kakaocdn.net/dn/DuNLJ/btqVAHFfifZ/47KUKPJ91zJA5GswXJeOb0/img.png](https://blog.kakaocdn.net/dn/DuNLJ/btqVAHFfifZ/47KUKPJ91zJA5GswXJeOb0/img.png)

대충 위의 코드를 스택으로 표현하면 위와 같습니다. 우리는 이제 size에 win[4] + size + buf[24] = 32를 입력한 후에 buf[24]와 size 부분을 의미없는 문자로 가득 채워버리고 win부분에 우리가 원하는 값인 ABCD를 넣어 줄껍니다.

![https://blog.kakaocdn.net/dn/bgMWfo/btqVAIKU0fy/xOWeJPE9K3r87ugRchnW2k/img.png](https://blog.kakaocdn.net/dn/bgMWfo/btqVAIKU0fy/xOWeJPE9K3r87ugRchnW2k/img.png)

공격이 성공하여 Theori 값이 출력되었습니다.

### Example 4

```c
// stack-4.c
#include <stdio.h>

int main(void) {
	char buf[32] = {0, };
	read(0, buf, 31);
	sprintf(buf, "Your Input is: %s\n", buf);
	puts(buf);
}
```

32byte의 buf를 0으로 초기화하고 31byte만큼의 데이터를 입력받은 뒤 buf에 저장합니다. 이후 sprintf 함수를 통해 buf에 값을 씁니다. 이 때, buf에는 Your Input is: 라는 문장도 함께 저장됩니다. 따라서 사용자가 아무것도 입력하지 않아도 buf에 이미 15byte만큼이 채워지기 때문에 17byte 이상을 사용자가 입력하게 되면 버퍼오버플로우가 발생합니다.

![https://blog.kakaocdn.net/dn/bzf8Qe/btqVAHrHowy/tvIMWuJn5CNKg0w4bQk4tk/img.png](https://blog.kakaocdn.net/dn/bzf8Qe/btqVAHrHowy/tvIMWuJn5CNKg0w4bQk4tk/img.png)


# 002. OOB (Out Of Boundary)

OOB (Out Of Boundary)는 **버퍼의 길이 범위를 벗어나는 인덱스에 접근할 때 발생하는 취약점** 입니다.

### Example 1

```c
// oob-1.c
#include <stdio.h>
int main(void) {
    int win;
    int idx;
    int buf[10];

    printf("Which index? ");
    scanf("%d", &idx);
    printf("Value: ");
    scanf("%d", &buf[idx]);
    printf("idx: %d, value: %d\n", idx, buf[idx]);
    if(win == 31337){
        printf("Theori{-----------redacted---------}");
    }
}
```

scanf 함수로 idx 값을 저장하고 buf[idx]에 입력한 값을 저장합니다. 이후 idx값과 buf[idx] 값을 출력합니다.

win의 값이 31337이 된다면 Theori{-----------redacted---------} 를 출력합니다 int buf[10]의 크기는 40byte이므로 41byte부터 데이터를 입력하면 존재하지 않는 인덱스에 접근이 가능합니다. buf[10]은 idx 변수이고 buf[11]은 win 변수이므로 buf[11]에 접근하여 win을 조작하면 될 것 같습니다.

![https://blog.kakaocdn.net/dn/bG5SqU/btqVIazUvfw/UbpyMUF4qpekPktt5UgP3K/img.png](https://blog.kakaocdn.net/dn/bG5SqU/btqVIazUvfw/UbpyMUF4qpekPktt5UgP3K/img.png)

### Example 2

```c
// oob-2.c
#include <stdio.h>
int main(void) {
    int idx;
    int buf[10];
    int win;

    printf("Which index? ");
    scanf("%d", &idx);

    idx = idx % 10;// 여기가 추가되었어요!printf("Value: ");
    scanf("%d", &buf[idx]);
    printf("idx: %d, value: %d\n", idx, buf[idx]);
    if(win == 31337){
        printf("Theori{-----------redacted---------}");
    }
}
```

첫 번째 예제와 비슷하게 idx값을 입력받고 buf[idx]에 값을 저장한 뒤 idx와 buf[idx]를 출력하는 코드입니다. 다만 idx에 입력한 값을 10으로 나눈 나머지를 idx에 저장하는 부분이 추가되었습니다. 얼핏보면 0~9까지의 값만 idx에 저장되는것처럼 보입니다. 하지만 C언어에서는 피연산자가 음수라면 나머지 연산의 결과도 음수로 만들 수 있습니다. 위 코드가 스택에 쌓이는 과정을 표현한다면 아래와 같습니다.

![https://blog.kakaocdn.net/dn/b0tVOG/btqVIcduzQK/Hq5H5eo7ECBF9K1tWFrBe0/img.png](https://blog.kakaocdn.net/dn/b0tVOG/btqVIcduzQK/Hq5H5eo7ECBF9K1tWFrBe0/img.png)

idx 값에 -1을 넣어 win 값을 참조하도록 만들고 31337 값을 넣어줍니다.

![https://blog.kakaocdn.net/dn/biFxre/btqVK9mJzIJ/8L0FkhipLs8P9MfSHgfhtK/img.png](https://blog.kakaocdn.net/dn/biFxre/btqVK9mJzIJ/8L0FkhipLs8P9MfSHgfhtK/img.png)

공격에 성공하여 Theori 값이 출력됩니다.

### Example 3

```c
//oob-3.c
#include <stdio.h>
int main(void) {
    int idx;
    int buf[10];
    int dummy[7];
    int win;
    printf("Which index? ");
    scanf("%d", &idx);

    if(idx < 0)
        idx = -idx;
    idx = idx % 10;// No more OOB!@!#!printf("Value: ");
    scanf("%d", &buf[idx]);
    printf("idx: %d, value: %d\n", idx, buf[idx]);
    if(win == 31337){
        printf("Theori{-----------redacted---------}");
    }
}
```

idx 값이 음수라면 양수로 만들어버리고 idx 값을 10으로 나눈 나머지를 저장해서 idx 범위를 0~9까지로 제한합니다.나머지 코드는 위와 동일합니다.여기서 buf[-8]이 된다면 win에 접근할 수 있을 것 같습니다.

![https://blog.kakaocdn.net/dn/Bnqgh/btqVzQ3AXsd/6wkdn6mWWG63GqNG2MyBE0/img.png](https://blog.kakaocdn.net/dn/Bnqgh/btqVzQ3AXsd/6wkdn6mWWG63GqNG2MyBE0/img.png)

여기서 우리가 알아야 할 것은 int 의 범위입니다. int형의 값의 범위는 아래와 같습니다.

- 2,147,483,648 ~ 2,147,483,647
- pow (2, 31) ~ pow (2, 31) -1

여기서 idx에 -2,147,483,648 값을 입력하게 된다면 어떨까요? if문에 의해서 idx가 음수이므로 2,147,483,648로 변하게 됩니다. 하지만 이는 int형의 범위를 초과합니다. 이는 signed 4byte int 에서 -2,147,483,648과 같아집니다. 따라서 -2147483648 % 10 = -8이므로 win에 접근할 수 있습니다.

![https://blog.kakaocdn.net/dn/cpdfeP/btqVAHrL9Qb/w0DSNIk6dxbRquBZLKOKdK/img.png](https://blog.kakaocdn.net/dn/cpdfeP/btqVAHrL9Qb/w0DSNIk6dxbRquBZLKOKdK/img.png)

# 003. Off-by-one

Off-by-one 취약점은 **경계 검사에서 하나의 오차가 있을 때 발생**하는 취약점입니다.

```c
// off-by-one-1.c
#include <stdio.h>
void copy_buf(char *buf, int sz) {
    char temp[16];

    for(i = 0; i <= sz; i++)
        temp[i] = buf[i];
}
int main(void) {
    char buf[16];

    read(0, buf, 16);
    copy_buf(buf, sizeof(buf));
}
```

main 함수에서 16byte의 문자열을 사용자로부터 입력받은 후 buf에 저장하고 copy_buf 함수의 인자로 buf와 sizeof(buf) 값을 전달합니다. copy_buf 함수에서 for문이 실행되는데 여기서 문제가 있습니다. 범위를 0부터 15까지로 제한했어야 하지만 <= 작거나 같다 구문 때문에 16까지 인덱스를 참조하게 됩니다. 실제로 temp[16]과 buf[16]은 존재하지 않기 때문입니다.

# 004. Format String Bug

포맷 스트링 버그는 printf나 sprintf와 같이 포맷 스트링을 사용하는 함수에서 발생하는 취약점입니다.

### Example 1

```c
// fsb-1.c
#include <stdio.h>

int main(void) {
    char buf[100] = {0, };

    read(0, buf, 100);
    printf(buf);
}

```

위 예제는 buf에 100byte를 입력받고 printf 함수를 통해 buf를 출력하는 예제입니다. 사용자가 "Hello" 나 "12345" 같은 문자열을 입력다면 printf("Hello"); printf("12345"); 와 같이 정상적으로 문자열이 출력됩니다. 하지만 %x %d 와 같은 포맷 스트링을 문자열로 입력한다면, printf("%x %d")와 같이 인자를 받을 수 있는 함수로 변해버립니다. 하지만 전해줄 인자가 없기 때문에 쓰레기 값을 출력하게 됩니다.

### Example 2

```c
// fsb-2.c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *fp = fopen("log.txt", "w");
    char buf[100] = {0, };

    read(0, buf, 100-1);

    fprintf(fp, "BUFFER-LOG: ");
    fprintf(fp, buf);

    fclose(fp);
    return 0;
}
```

log.txt 파일을 읽기 전용으로 열어서 read 함수로 99byte만큼 buf에 데이터를 저장합니다.

fprintf의 원형은 아래와 같습니다.

```c
#include <stdio.h>

int fprintf(FILE* stream, const char* format, ...);
```

fprintf(fp, "BUFFER-LOG: %s "); 와 같이 포맷스트링이 들어가야 할 곳에 사용자의 입력이 들어갑니다. 예제 1번과 마찬가지로 %x, %d 같은 포맷 스트링을 입력하면 의도치 않은 값이 파일에 저장됩니다. 포맷 스트링 버그는 함수의 인자만 잘 검토하면 막기 쉽습니다. 최근에는 컴파일러에서 경고 메시지를 출력하기 때문에 잘 발생하지 않는 취약점입니다.

### Example 3

```c
// fsb-easy.c
#include <stdio.h>

int main(void) {
    int flag = 0x41414141;
    char buf[32] = {0, };

    read(0, buf, 31);
    printf(buf);
}
```

위 예제는 사용자의 입력을 31byte만큼 printf로 buf를 출력하는 예제입니다. 여기에 포맷 스트링을 입력해 버린다면 의도치 않은 값을 출력할 수 있습니다.

![https://blog.kakaocdn.net/dn/Hdad4/btqVIKabNUK/p8aPsgdAyWApbTNrAgAQz0/img.png](https://blog.kakaocdn.net/dn/Hdad4/btqVIKabNUK/p8aPsgdAyWApbTNrAgAQz0/img.png)

따라서 %x를 10번 입력하여 flag 값을 출력하도록 합니다.

![https://blog.kakaocdn.net/dn/u3Sud/btqV083vZGg/tj53t6pmzCPueBxjETLULK/img.png](https://blog.kakaocdn.net/dn/u3Sud/btqV083vZGg/tj53t6pmzCPueBxjETLULK/img.png)

# 005. Double Free & Use After Free

Double Free 취약점과 UAF (Use After Free) 취약점은 동적 메모리 관리에서 나타납니다. 이미 해제된 메모리를 다시 한 번 해제하거나 (Double Free), 해제된 메모리에 접근해서 값을 쓸 수 있는 문제 (UAF)가 있습니다.

### Example 1

![https://blog.kakaocdn.net/dn/cBq5Qv/btqV2Vo58SN/VVhi0WHLXSGcGP7WZUt6Y1/img.png](https://blog.kakaocdn.net/dn/cBq5Qv/btqV2Vo58SN/VVhi0WHLXSGcGP7WZUt6Y1/img.png)

위 예제는 a와 b에 100byte 만큼의 메모리를 할당하고 Hello World! 문자열을 복사한 뒤 출력하는 코드입니다.하지만 메모리를 해제할 때 이미 해제된 메모리를 다시 한번 해제하는 경우가 발생하면 공격자에 의해 프로그램의 실행 흐름이 변경될 수 있습니다.

### Example 2

![https://blog.kakaocdn.net/dn/cqwwDl/btqV09g61tJ/2rc17AUclO15N67nwnV4Y1/img.png](https://blog.kakaocdn.net/dn/cqwwDl/btqV09g61tJ/2rc17AUclO15N67nwnV4Y1/img.png)

메모리의 동적 할당은 Heap 영역에서 발생합니다. 100byte크기의 a가 메모리에 동적할당되고 Hello World! 문자열이 복사된 후 출력됩니다. 그리고 a를 해제하고 100byte크기의 b를 메모리에 동적할당 후Hello Pwnable! 문자열이 복사된 후 출력됩니다. 

**여기서 메모리a와 메모리b가 힙 영역에서 같은 주소를 가리키고 있다는 점을 고려해야합니다.** 새로운 메모리 영역을 할당할 때 메모리를 효율적으로 관리하기 위해 기존에 해제되었던 메모리가 그대로 반환되어 일어나는 일입니다. 

그래서 이미 해제된 메모리 a에 접근하여 Hello World! 문자열을 복사한다면 b 또한 영향을 받기 때문에 문제가 발생할 수 있습니다. 위의 코드를 컴파일하여 실행하면 아래와 같은 출력결과를 보실 수 있습니다.

![https://blog.kakaocdn.net/dn/H0MVN/btqV0FgcNgX/CZKG4m5b5jf2hlZTxrkEQK/img.png](https://blog.kakaocdn.net/dn/H0MVN/btqV0FgcNgX/CZKG4m5b5jf2hlZTxrkEQK/img.png)

분명히 a에 Hello World! 문자열을 복사했지만 b를 출력하면 a에 복사한 문자열로 바뀌어 출력되는것을 확인할 수 있습니다.

# 006. 초기화되지 않은 메모리

변수를 선언하거나 인스턴스를 생성할 때, 프로그래머가 의도한 경우를 제외하고는 반드시 초기화해야 합니다. **메모리를 초기화하지 않는다면 쓰레기 값이 들어가고 이것이 문제를 발생**시킬 수 있습니다.

### Example

![https://blog.kakaocdn.net/dn/phLrQ/btqWjquHjWz/4YEl7D1YZPqa1QYNgSWxGK/img.png](https://blog.kakaocdn.net/dn/phLrQ/btqWjquHjWz/4YEl7D1YZPqa1QYNgSWxGK/img.png)

위 예제는 이름의 길이를 입력받고 그 길이가 100 미만이면 메모리를 동적할당합니다. read 함수는 name_len 데이터 길이만큼 p.name에 저장할 수 있습니다. 여기서 **초기화되지 않은 값의 사용으로 인해 문제가 발생**합니다.

1. read함수는 입력받을 때 널 바이트와 같은 별도의 구분자를 붙이지 않습니다. 따라서 name에 할당된 메모리를 초기화하지 않으면 다른 메모리가 출력될 수 있습니다.

2. name_len 변수의 값이 100 이상이거나 같을 경우에 p.name 값은 쓰레기값이 됩니다. 만약 이 값을 조작한다면 read함수를 통해 데이터를 입력받을 때 메모리 주소에 원하는 값을 쓸 수 있습니다.

# 007. Integer issues

C언어나 C++ 언어를 사용할 때 **정수의 형 변환을 제대로 고려하지 못하면 취약점이 발생**합니다. 아래는 사이트는 자료형들의 표현 범위입니다.

[docs.microsoft.com/ko-kr/cpp/cpp/data-type-ranges?view=msvc-160](https://docs.microsoft.com/ko-kr/cpp/cpp/data-type-ranges?view=msvc-160)

---

### **< 묵시적 형 변환 >**

**대입 연산**의 경우 좌변과 우변의 자료형이 다를 경우 묵시적으로 형 변환이 일어나게 됩니다. 작은 정수 자료형에 큰 정수를 저장하는 경우, 작은 정수의 크기에 맞춰서 상위 바이트가 소멸됩니다.

![https://blog.kakaocdn.net/dn/cQ0udh/btqWc82eNQN/A5EQwdkYOuXQH4Tk5Iowo0/img.png](https://blog.kakaocdn.net/dn/cQ0udh/btqWc82eNQN/A5EQwdkYOuXQH4Tk5Iowo0/img.png)

double 형 변수 num1을 정의하고 12.34를 대입한 후, int 형 변수 num2에 num1을 대입한 후 출력하게 되면 소수점을 무시한 12만 출력되는것을 확인할 수 있습니다.

![https://blog.kakaocdn.net/dn/8kBxI/btqWjqnXQm2/f1HXCjzQnc6ArO5NkJBoEk/img.png](https://blog.kakaocdn.net/dn/8kBxI/btqWjqnXQm2/f1HXCjzQnc6ArO5NkJBoEk/img.png)

**정수 승격**은 char이나 short 같은 자료형이 연산될 때 일어납니다. 크기가 4byte보다 작은 자료형의 값을 계산할 때는 int형으로 변환하여 연산이 수행됩니다.

![https://blog.kakaocdn.net/dn/daKkDo/btqV2WauIse/EjKnagKOIbxE216ZdxoHk1/img.png](https://blog.kakaocdn.net/dn/daKkDo/btqV2WauIse/EjKnagKOIbxE216ZdxoHk1/img.png)

위 코드를 실행하면 다음 결과가 나옵니다.

![https://blog.kakaocdn.net/dn/ceLxU5/btqV2atj76v/zp61DoBAtQ6J6eTmGW0Zb0/img.png](https://blog.kakaocdn.net/dn/ceLxU5/btqV2atj76v/zp61DoBAtQ6J6eTmGW0Zb0/img.png)

분명히 크기가 2byte인 short num1과 num2끼리 연산을 했는데 연산결과는 크기가 4byte인 int형으로 되었다는것을 확인할 수 있습니다.

**피연산자가 불일치** 할 경우에도 형 변환이 일어납니다.

int < long < long long < float < double< long double 순으로 변환되며, 작은 바이트에서 큰 바이트로, 정수에서 실수로 형 변환이 일어나게 됩니다. 예를 들면, int형과 double형을 더하면 int형이 double형으로 변환된 후 연산이 진행됩니다.

![https://blog.kakaocdn.net/dn/mE96x/btqV0EaBu02/9aUewlWbNMsuCWKlix85H0/img.png](https://blog.kakaocdn.net/dn/mE96x/btqV0EaBu02/9aUewlWbNMsuCWKlix85H0/img.png)

위 코드는 사용자로부터 len값을 입력받고 len+1 만큼 메모리를 동적할당 받고, read 함수를 통해 len 크기 만큼 buf에 데이터를 입력받습니다.

만약 공격자가 len 값으로 -1을 넣는다면 어떻게 되는지 보겠습니다. 11행에서 buf = (char*)malloc(0) 가 호출되고 18행에서 read (0, buf, -1) 이 호출됩니다. read 함수의 원형은 아래와 같습니다.

```c
read(int fd, void *buf, size_t nbytes);
```

read 함수의 세 번째 인자는 size_t 형이므로 묵시적 형 변환이 일어납니다. 따라서 read 함수를 호출할 때, 32비트 아키텍처라고 가정하면 read(0, buf, pow(2, 32) -1) 이 호출됩니다. 그러므로 지정된 크기의 버퍼를 넘는 데이터를 넣을 수 있어 힙 오버플로우가 발생합니다.

![https://blog.kakaocdn.net/dn/nM3IN/btqV2WIlZct/Zf0qNXEd5r6McJXkVwtluk/img.png](https://blog.kakaocdn.net/dn/nM3IN/btqV2WIlZct/Zf0qNXEd5r6McJXkVwtluk/img.png)

위 코드의 create_tbl 함수는 width와 height, row를 인자로 받고 테이블을 초기화한다. 그런데 6행의 n에 pow(2, 32)가 넘어가는 값이 저장된다면 문제가 발생합니다. 

pow(2, 32) = 4,294,967,296 

unsigned int형의 값의 범위는 0 ~ 4,294,967,295

width값이 65,536이고 height값이 65,537이라면 n에 4,295,032,832가 들어가야합니다. n은 pow(2, 32) + 65,536과 같으므로 실제로 저장되는 값은 65,536이 됩니다. 그러나 memcpy 함수에서 반복문을 순회하면서 메모리를 복사하기 때문에 버퍼 오버플로우가 발생하게 됩니다.

---

### **Q. 어떤 line이 취약할까요?**

![https://blog.kakaocdn.net/dn/b4wowd/btqV19Vwx41/iHbmTLd02hKb7fKKFRszvK/img.png](https://blog.kakaocdn.net/dn/b4wowd/btqV19Vwx41/iHbmTLd02hKb7fKKFRszvK/img.png)

8번째 라인을 보면 길이를 검사하는 과정인데 사용자가 입력한 값이 0 미만이거나 length + 1 값이 MAX_SIZE보다 크거나 같다면 종료시킵니다. 이때 length에 int형 최대값 0x7FFFFFFF (2,147,483,647) 값을 넣어버리면 0x7FFFFFFF (2,147,483,647) < 0은 false 2,147,483,647에 1을 더해버리면 -2,147,483,648이 되면서2,147,483,648 >= 0x8000 도 false가 됩니다. 그러면 13번째 line에서 read(fd, buf, 0x7FFFFFFF)가 호출되어 힙 오버플로우가 발생하게 됩니다.

