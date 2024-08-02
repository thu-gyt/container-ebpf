#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include "agent_util.h"

#define RING_BUFFER_POLL_TIMEOUT    100 
#define DEBUG_FS "/sys/kernel/debug/tracing/trace_pipe"
#define PID_MAP_PATH     "/sys/fs/bpf/kernel/pid_map"
#define SYSCALL_COUNT_MAP_PATH     "/sys/fs/bpf/kernel/pid_syscount_map"
char *pid_filter_file = NULL;


void read_trace_pipe(void) {
    int trace_fd;
    trace_fd = open(DEBUG_FS, O_RDONLY, 0);
    if (trace_fd < 0) {
        printf("Failed to open %s\n", DEBUG_FS);  // DEBUGFS is a macro defined in debug.h
        return;
    }

    while (1) {
        static char buf[4096];
        ssize_t sz;

        sz = read(trace_fd, buf, sizeof(buf) - 1);
        if (sz > 0) {
            buf[sz] = 0;
            puts(buf);
        }
    }

    close(trace_fd);
}


int collect_rb(void *ctx, void *data, size_t data_sz) {


    return 0;
}

int run(struct ring_buffer **rb) {
    int ret = 0;

    while (1) {
        ret = ring_buffer__poll(*rb, RING_BUFFER_POLL_TIMEOUT);

        if (ret == -EINTR) {
            fprintf(stdout, "Interrupted, exiting gearbox agent\n");
            ret = 0;
            break;
        }
        
        if (ret < 0) {
            fprintf(stderr, "Error polling ring buffer: %s\n", strerror(errno));
            break;
        }
    }

    return ret;
}

void parse_args(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "c:")) != -1) {
        switch (opt) {
            case 'c':
                pid_filter_file = optarg;
                printf("PID filter file: %s\n", pid_filter_file);
                break;
            default:
                fprintf(stderr, "Usage: %s -c <pid_filter_file>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
}





int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    parse_args(argc, argv);
    read_pids_and_update_map(pid_filter_file, PID_MAP_PATH);


    // read_trace_pipe();
    while (1) {

        read_syscall_counts(SYSCALL_COUNT_MAP_PATH);
        sleep(10);
    }

    if (rb) {
        ring_buffer__free(rb);
    }
    return 0;
}
