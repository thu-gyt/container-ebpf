# 打开并读取文件
with open('1.txt', 'r') as file:
    lines = file.readlines()

# 初始化字典来存储每个 PID 对应的系统调用计数
syscall_count = {}

# 遍历文件的每一行
for line in lines:
    parts = line.split()
    pid = parts[4].strip('()')
    syscall = parts[6]
    
    if pid not in syscall_count:
        syscall_count[pid] = {}
    
    if syscall not in syscall_count[pid]:
        syscall_count[pid][syscall] = 0
    
    syscall_count[pid][syscall] += 1

# 打印每个 PID 对应的系统调用计数
for pid, syscalls in syscall_count.items():
    print(f"PID: {pid}")
    for syscall, count in syscalls.items():
        print(f"  {syscall}: {count}")