import time
import zlib
from scapy.all import *
import multiprocessing
import sys

import socket
import struct

# 这段代码使用Python进行网络数据包的捕获和处理，主要依赖于Scapy和multiprocessing库。
# 它定义了两个主要功能：ip2int和int2ip用于IP地址和整数之间的转换，
# 以及使用多进程监听网络流量并处理接收到的数据包。

# ip2int函数将点分十进制的IP地址字符串转换为32位的网络字节序整数。
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

# int2ip函数将32位的网络字节序整数转换回点分十进制的IP地址字符串。
def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def listener(queue, trial_number, stop_total_packets):
    k = 0  # 初始化变量k，它在这里未被使用
    total_packets = 0  # 用于追踪处理的总数据包数量
    distance_metric = {}  # 初始化字典，虽然在这段代码中未使用
    fw = open(trial_number, "w")  # 打开（并清空）一个文件用于写入数据包信息
    fw.close()  # 立即关闭文件，这次操作主要是为了清空文件内容
    while True:  # 开始无限循环，等待并处理数据包信息
        data = queue.get()  # 从队列中获取数据包信息，这是一个阻塞操作
        # 从队列中取得的数据包含多个部分，分别赋值给不同的变量
        k = data[0]  # TTL值
        pkt_id = data[1]  # 数据包ID
        switch_id = data[2]  # 源MAC地址转换成的整数
        digest = data[3]  # 目的MAC地址转换成的整数
        checksum = data[4]  # IP头的校验和
        src_ip = data[5]  # 源IP地址转换成的整数
        dst_ip = data[6]  # 目的IP地址转换成的整数
        final_results = {}  # 初始化字典，虽然在这段代码中未使用
        total_packets += 1  # 处理的数据包数量加一
        if total_packets == 1:  # 如果是第一个数据包，记录开始时间（虽然开始时间未被使用）
            start_time = time.time()
        # 重新打开文件追加数据包信息
        fw = open(trial_number, "a")
        # 将数据包的相关信息写入文件，包括处理的总包数、TTL、数据包ID、转换的MAC地址、校验和、源和目的IP地址
        fw.write(f"{total_packets},{k},{pkt_id},{switch_id},{digest},{checksum},{src_ip},{dst_ip}\n")
        fw.close()  # 关闭文件




def parent_callback(queue):
    # 定义捕获数据包时的回调函数
    def pkt_callback(pkt):
        # 获取以太网层和IP层的信息
        ethernet_header = pkt.getlayer(Ether)
        src_mac = ethernet_header.src  # 源MAC地址
        dst_mac = ethernet_header.dst  # 目的MAC地址
        ip_header = pkt.getlayer(IP)
        src_ip = ip_header.src  # 源IP地址
        dst_ip = ip_header.dst  # 目的IP地址
        ecn = ip_header.tos  # 服务类型字段，用于ECN
        pkt_id = ip_header.id  # 数据包的ID
        ttl = ip_header.ttl  # 生存时间
        chksum = ip_header.chksum  # IP头的校验和
        # 检查ECN字段是否为1，如果是，则处理数据包
        if ecn == 1:
            k = ttl  # 使用TTL作为特定变量k
            # 将MAC地址中的非数字字符去除并转换为整数
            src_mac_int = int(src_mac.translate(None, ":.- "), 16)
            dst_mac_int = int(dst_mac.translate(None, ":.- "), 16)
            checksum = int(chksum)  # 直接使用IP头的校验和
            # 将处理后的信息放入队列中
            queue.put((k, pkt_id, src_mac_int, dst_mac_int, checksum, ip2int(src_ip), ip2int(dst_ip)))
    return pkt_callback
    # 返回内部定义的回调函数

manager = multiprocessing.Manager()
# 创建一个管理器对象，用于跨进程共享数据
queue = manager.Queue()
# 通过管理器创建一个队列，用于进程间通信
pool = multiprocessing.Pool(1)
# 创建一个包含一个工作进程的进程池，用于异步任务执行

f = open("config", "r")
# 打开名为"config"的配置文件进行读取
for line in f:
    line = line.strip().split("=")
    # 移除每行的首尾空格并按"="分割，得到配置项的键和值
    type = line[0]
    data = line[1]
    # 分别获取配置项的键（type）和值（data）
    if type == "max_bit_range":
        max_bit_range = int(data)
    if type == "global_hash_range":
        global_hash_range = int(data)
    if type == "receiver_interface":
        receiver_interface = data
    if type == "receiver_ip":
        receiver_ip = data
    if type == "common_log":
        common_log = data
    if type == "total_packets":
        total_packets = int(data)
    if type == "iterations":
        iterations = int(data)
    # 根据配置项的键，将相应的值赋给对应的变量，并进行必要的类型转换
f.close()
# 关闭配置文件

trial_number = sys.argv[1]
# 从命令行参数获取试验编号
watcher = pool.apply_async(listener, (queue, trial_number + "_" + str(global_hash_range), total_packets * iterations))
# 使用进程池异步执行listener函数，传递队列、试验编号和根据总数据包数及迭代次数计算的停止条件
sniff(iface=receiver_interface, prn=parent_callback(queue), filter="dst net " + receiver_ip, store=0)
# 使用Scapy的sniff函数在指定的网络接口上捕获目的IP地址为配置中指定receiver_ip的数据包
# 不存储捕获到的数据包（store=0），而是使用parent_callback(queue)函数处理每个捕获到的数据包
