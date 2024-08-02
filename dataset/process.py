# 打开并读取文件
with open('syscalls.txt', 'r') as file:
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


def count_non_zero_elements(data_list):
    return sum(1 for element in data_list if element != 0)


normal_data = []
abnormal_data = []
max_pid1 = 0
max_num1 = 0
max_pid2 = 0
max_num2 = 0

for filedir in ['normal', 'cve-2016-9962']:
    pid_syscall_count = {}
    for i in range(1,4):
        with open(f'./{filedir}/{i}.txt', 'r') as file:
            lines = file.readlines()



        # 遍历文件的每一行
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            pid = parts[4].strip('()') + f'_{i}'
            syscall = parts[6]
            
            if pid not in pid_syscall_count:
                pid_syscall_count[pid] = [0 for _ in range(len(syscall_map))]
            
            if syscall not in syscall_map:
                continue
            syscall_id = syscall_map[syscall]
            pid_syscall_count[pid][syscall_id] += 1
            

        for pid, syscalls in pid_syscall_count.items():
            if sum(syscalls) > 200:
                if filedir == 'normal':
                    normal_data.append(syscalls)
                    num = count_non_zero_elements(syscalls)
                    if num > max_num1:
                        max_num1 = num
                        max_pid1 = pid
                else:
                    abnormal_data.append(syscalls)
                    num = count_non_zero_elements(syscalls)
                    if num > max_num2:
                        max_num2 = num
                        max_pid2 = pid



print(max_pid1, max_num1)
print(max_pid2, max_num2)

import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler, MinMaxScaler

normal_labels = [0] * len(normal_data)
abnormal_labels = [1] * len(abnormal_data)

# 合并数据和标签
data = normal_data + abnormal_data
labels = normal_labels + abnormal_labels



scaler = MinMaxScaler()
data_scaled = scaler.fit_transform(data)

# 使用 KMeans 进行分类
kmeans = KMeans(n_clusters=2, random_state=0)
kmeans.fit(data_scaled)
predicted_labels = kmeans.labels_

# 计算分类准确度
accuracy = accuracy_score(labels, predicted_labels)
print(f"分类准确度: {accuracy:.2f}")
