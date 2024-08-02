#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>

int main() {
    // Print the process ID (PID)
    printf("PID: %d\n", getpid());

    // Seed the random number generator
    srand(time(NULL));

    // Enter the loop
    while (1) {


        read(0, NULL, 0);

        // Trigger the system call
        syscall(46);

        printf("syscall!\n");
        // Sleep for 2 seconds
        sleep(2);
    }

    return 0;
}