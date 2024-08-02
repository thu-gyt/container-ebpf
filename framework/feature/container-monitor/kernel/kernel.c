#include "all.h"
#include "utils.h"
// #include "structs.h"
#include "maps.h"



// SEC("tracepoint/syscalls/sys_enter_read")
// int bpf_prog(void *ctx)
// {
// 	// char msg[] = "Hello, BPF World!";
// 	// bpf_trace_printk(msg, sizeof(msg));

// 	u32 tgid = bpf_get_current_pid_tgid() >> 32;
// 	// u32 tgid = (u32) pid_tgid;
// 	if(tgid == 2421068){
// 		bpf_printk("1-read enter (tracepoint) - PID: %u\n", tgid);
// 	}

// 	if (is_filtered_pid(tgid))
// 	{
// 		return 0;
// 	}

// 	bpf_printk("execve enter (tracepoint) - PID: %u\n", tgid);

// 	return 0;
// }

SEC("tracepoint/raw_syscalls/sys_enter")
int syscall_enter(struct bpf_raw_tracepoint_args *ctx)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	u32* count;

	if (is_filtered_pid(tgid))
	{
		return 0;
	}

	int sys_id = ctx->args[1];
	u64 key = (u64)tgid << 32 | sys_id;
	count = bpf_map_lookup_elem(&pid_syscount_map, &key);
	if(count){
		*count += 1;
		bpf_printk("syscall enter PID: %u, SYS_ID: %d num: %u\n", tgid, sys_id, *count);
	}else{
		u32 zero = 0;
		bpf_map_update_elem(&pid_syscount_map, &key, &zero, BPF_ANY);
		bpf_printk("syscall enter PID: %u, SYS_ID: %d num: %u\n", tgid, sys_id, 1);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";