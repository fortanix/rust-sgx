#include <stdio.h>
#include <unistd.h>

int main() {
    int cnt = 0;
    while(1) {
            printf("[%3i] Hello world!\n", cnt);
            sleep(1);
            cnt++;
    }

    return 0;
}
