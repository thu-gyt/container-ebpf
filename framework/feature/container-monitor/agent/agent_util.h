#ifndef __AGENT_UTIL_H__
#define __AGENT_UTIL_H__

#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int read_pids_and_update_map(const char *pid_config_path, const char *pid_map_path)
{
    int ret = 0;
    FILE *fp;
    char line[1024];

    fp = fopen(pid_config_path, "r");
    if (!fp)
    {
        fprintf(stderr, "Failed to open file: %s because %s\n", pid_config_path, strerror(errno));
        ret = -1;
        return ret;
    }

    int pid_map_fd = bpf_obj_get(pid_map_path);
    if (pid_map_fd < 0)
    {
        fprintf(stderr, "Failed to get BPF map for PID filtering: %s because %s\n", pid_map_path, strerror(errno));
        ret = -1;
        goto cleanup;
    }

    while (fgets(line, sizeof(line), fp))
    {
        __u32 pid, value;
        sscanf(line, "%u %u", &pid, &value);

        if (pid > 0)
        {
            if (bpf_map_update_elem(pid_map_fd, &pid, &value, BPF_ANY) != 0)
            {
                fprintf(stderr, "Failed to update BPF map for PID %d: %s\n", pid, strerror(errno));
                ret = -1;
                break;
            }
            else
            {
                fprintf(stderr, "PID %d added to the map successfully.\n", pid);
            }
        }
        else
        {
            fprintf(stderr, "Invalid PID: %s\n", line);
        }
    }

    close(pid_map_fd);

cleanup:
    fclose(fp);
    return ret;
}

void read_syscall_counts(const char *syscall_count_map_path)
{
    printf("Reading syscall counts\n");
    int pid_syscount_map_fd = bpf_obj_get(syscall_count_map_path);
    if (pid_syscount_map_fd < 0)
    {
        fprintf(stderr, "Failed to get BPF map for PID syscall count: %s because %s\n", syscall_count_map_path, strerror(errno));
        return;
    }

    __u64 key, next_key;
    __u32 value;
    int ret = 0;

    while (1)
    {
        ret = bpf_map_get_next_key(pid_syscount_map_fd, &key, &next_key);
        if (ret)
        {
            if (errno == ENOENT)
            {
                // No more keys
                break;
            }
            else
            {
                printf("Failed to get next key: %s\n", strerror(errno));
                break;
            }
        }
        if (bpf_map_lookup_elem(pid_syscount_map_fd, &next_key, &value) == 0)
        {
            if(value == 0){
                continue;
            }
            __u32 pid = next_key >> 32;
            __u32 sysid = next_key & 0xFFFFFFFF;
            printf("PID: %u, sysID: %u count: %u\n", pid, sysid, value);
            value = 0;
            bpf_map_update_elem(pid_syscount_map_fd, &next_key, &value, BPF_ANY);
        }
        key = next_key;
    }
    close(pid_syscount_map_fd);

    printf("--------------------\n");
}

#endif // __AGENT_UTIL_H__