nomral = '9361_3'
anomaly = '1042213_1'

# 打开并读取文件
with open('../syscalls.txt', 'r') as file:
    lines = file.readlines()

# 初始化字典来存储系统调用名称到 ID 的映射
syscall_map = {}

# 遍历文件的每一行
line_id = 0
for line in lines:
    parts = line.split()
    syscall_id = int(parts[0])
    syscall_name = parts[1]
    
    syscall_map[syscall_name] = line_id
     
    line_id += 1

fp = open(f"../normal/{nomral.split('_')[1]}.txt", 'r')
fp2 = open(f"./normal_seq.txt", 'w')
for line in fp.readlines():
    pid = line.split()[4].strip('()')
    syscall = line.split()[6]
    if pid == nomral.split('_')[0]:
        if syscall in syscall_map:
            print(syscall_map[syscall])
            fp2.write(str(syscall_map[syscall]) + '\n')
fp2.close()
fp.close()
fp = open(f"../cve-2016-9962/{anomaly.split('_')[1]}.txt", 'r')
fp2 = open(f"./anomaly_seq.txt", 'w')
for line in fp.readlines():
    if len(line.split()) < 4:
        continue
    pid = line.split()[4].strip('()')
    syscall = line.split()[6]
    if pid == anomaly.split('_')[0]:
        if syscall in syscall_map:
            print(syscall_map[syscall])
            fp2.write(str(syscall_map[syscall]) + '\n')