#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <time.h>

#define MAX_SYSCALLS 1000

int main() {
    FILE *file;
    int syscall_ids[MAX_SYSCALLS];
    int count = 0;

    // 读取文件 normal_seq.txt
    file = fopen("normal_seq.txt", "r");
    if (file == NULL) {
        perror("无法打开文件");
        return 1;
    }

    while (fscanf(file, "%d", &syscall_ids[count]) != EOF && count < MAX_SYSCALLS) {
        count++;
    }
    fclose(file);

    printf("当前进程 PID: %d\n", getpid());
    getchar();

    // 按序执行对应的系统调用
    for (int i = 0; i < count; i++) {
        int syscall_id = syscall_ids[i];
        // printf("执行系统调用 ID: %d\n", syscall_id);
        syscall(syscall_id);
        // struct timespec ts;
        // ts.tv_sec = 0;
        // ts.tv_nsec = 100 * 1000000L; // 100 毫秒
        // nanosleep(&ts, NULL);
    }

    return 0;
}