from subprocess import Popen  # 引入Popen，用于创建子进程
import os  # 引入os模块，提供了与操作系统交互的功能
import time  # 引入time模块，提供了与时间相关的功能
import sys  # 引入sys模块，提供了访问与Python解释器紧密相关的变量和函数
import networkx as nx  # 引入networkx库，用于创建、操作复杂网络的结构、动态和功能

from p4utils.utils.topology import Topology  # 从p4utils.utils.topology模块引入Topology类，用于处理网络拓扑

class Experiment:  # 定义一个名为Experiment的类
	def __init__(self, length, exp_ranges,):  # 类的初始化方法
		self.length = length  # 将传入的length参数赋值给self.length属性
		self.exp_ranges = exp_ranges  # 将传入的exp_ranges参数赋值给self.exp_ranges属性
		self.original_path = []  # 初始化一个空列表，用于存储原始路径
		self.all_switches = set()  # 初始化一个空集合，用于存储所有的交换机
		self.all_links = set()  # 初始化一个空集合，用于存储所有的链接
		self.G = nx.Graph()  # 创建一个空的无向图
		self.host_ips = {}  # 初始化一个空字典，用于存储主机的IP地址
		self.switch_mapper = {}  # 初始化一个空字典，用于映射交换机和端口
		self.thrift_port = {}  # 初始化一个空字典，用于存储thrift端口信息

		for i in range(0, length):  # 遍历从0到length的整数
			self.all_switches.add("s"+str(i))  # 向all_switches集合添加交换机，名称为's'+当前的整数值转为字符串
			self.original_path.append("s"+str(i))  # 向original_path列表添加交换机的名称
		for i in range(0, length-1):  # 遍历从0到length-1的整数
			self.all_links.add(("s"+str(i), "s"+str(i+1)))  # 向all_links集合添加一对交换机，表示它们之间的链接

		self.exp_count = 0  # 初始化实验计数器为0
		self.max_bit_range = 255  # 设置最大比特范围为255
		self.all_done = set()  # 初始化一个空集合，用于跟踪完成的实验范围
		self.global_hash_range = 1000000  # 设置全局哈希范围为1000000

	def update_graph(self):  # 定义一个方法，用于更新图
		for switch in self.all_switches:  # 遍历所有交换机
			host = switch.replace("s", "h")  # 将交换机的名称中的's'替换为'h'，得到对应的主机名称
			self.G.add_node(switch)  # 向图中添加一个交换机节点
			self.G.add_node(host)  # 向图中添加一个主机节点

		for link in self.all_links:  # 遍历所有链接
			node_1 = link[0]  # 获取链接的第一个节点
			node_2 = link[1]  # 获取链接的第二个节点
			self.G.add_edge(node_1, node_2)  # 在图中添加一条边，连接这两个节点

	def obtain_mininet_topo(self):  # 定义一个方法，用于获取Mininet的拓扑结构
		topo = Topology(db="topology.db")  # 创建一个Topology对象，使用'topology.db'数据库
		for switch in self.all_switches:  # 遍历所有交换机
			if switch not in self.switch_mapper:  # 如果当前交换机不在switch_mapper字典中
					self.switch_mapper[switch] = {}  # 在switch_mapper字典中为当前交换机创建一个空字典

			host = switch.replace("s", "h")  # 获取对应的主机名称
			host_details = topo.node(host)  # 获取主机的详细信息
			ip_address = host_details[switch]["ip"].split("/")[0]  # 从主机详细信息中提取IP地址
			self.host_ips[host] = ip_address  # 将IP地址存储在host_ips字典中

			switch_details = topo.node(switch)  # 获取交换机的详细信息
			self.thrift_port[switch] = switch_details["thrift_port"]  # 从交换机详细信息中提取thrift端口，并存储在thrift_port字典中

			for interface, port in switch_details["interfaces_to_port"].items():  # 遍历交换机的接口和端口信息
				if interface != "lo":  # 如果接口名称不是'lo'
					node = switch_details["interfaces_to_node"][interface]  # 获取接口对应的节点名称
					self.switch_mapper[switch][node] = port  # 在switch_mapper字典中存储接口和端口的映射关系

	def generate_rules(self):  # 定义一个名为generate_rules的方法
		for switch in self.all_switches:  # 遍历所有的交换机
			host = switch.replace("s", "h")  # 获取对应的主机名称
			fw = open("rules/" + switch + "-commands.txt", "w")  # 打开或创建一个文件用于写入交换机的命令
			fw.write("table_clear dmac\n")  # 清除dmac表的所有条目
			fw.write("table_clear ttl_rules\n\n")  # 清除ttl_rules表的所有条目
			fw.write("table_add dmac forward " + self.host_ips[host] + " => " + str(self.switch_mapper[switch][host]) + "\n")  # 添加一条规则，用于将数据包转发到对应主机

			for switch_1 in self.all_switches:  # 再次遍历所有交换机
				if switch == switch_1:  # 如果是当前交换机本身，则跳过
					continue
				destination_host = switch_1.replace("s", "h")  # 获取目标交换机对应的主机名称
				try:
					p = nx.shortest_path(self.G, source=switch, target=switch_1)  # 尝试获取从当前交换机到目标交换机的最短路径
				except:
					continue  # 如果无法获取路径，则跳过当前循环
				fw.write("table_add dmac forward " + self.host_ips[destination_host] + " => " + str(self.switch_mapper[switch][p[1]]) + "\n")  # 为到达目标主机的数据包添加转发规则

			switch_id = switch.replace("s", "")  # 获取交换机的编号
			ttl = 255  # 设置TTL的初始值
			while ttl > 0:  # 当TTL大于0时执行循环
				approx = int(self.global_hash_range / (256 - ttl))  # 根据TTL值计算哈希范围的近似值
				fw.write("table_add ttl_rules copy_to_metadata " + str(ttl) + " => " + str(approx) + " " + str(switch_id) + " " + str(self.max_bit_range) + "\n")  # 为每个TTL值添加规则，用于处理数据包的TTL
				ttl = ttl - 1  # TTL递减
			fw.close()  # 关闭文件

		for node, port in self.thrift_port.items():  # 遍历所有的thrift端口
			os.system("simple_switch_CLI --thrift-port " + str(port) + " < rules/" + str(node) + "-commands.txt > /dev/null")  # 执行命令，使用simple_switch_CLI工具将规则加载到对应的交换机

	def gen_config(self, receiver_interface, receiver_ip, sender_ip):
		fw = open("config", "w")  # 打开或创建一个名为"config"的文件用于写入
		fw.write("receiver_interface=" + receiver_interface + "\n")  # 写入接收者的网络接口
		fw.write("max_bit_range=" + str(self.max_bit_range) + "\n")  # 写入最大比特范围
		fw.write("global_hash_range=1000000\n")  # 写入全局哈希范围的值
		fw.write("receiver_ip=" + receiver_ip + "\n")  # 写入接收者的IP地址
		fw.write("sender_ip=" + sender_ip + "\n")  # 写入发送者的IP地址
		fw.write("common_log=common_log\n")  # 指定公共日志文件的名称
		fw.write("total_packets=5000\n")  # 写入要发送的总数据包数
		fw.write("iterations=1")  # 写入迭代次数
		fw.close()  # 关闭文件

	def run(self):  # 定义run方法，用于执行实验
		while True:  # 无限循环
			for exp_range in self.exp_ranges:  # 遍历实验范围
				path = self.original_path[:exp_range]  # 获取实验的路径
				exp_name = str(len(path))  # 获取实验名称
				total_runs = len(path)  # 获取总运行次数

				self.generate_rules()  # 生成规则

				while True:  # 再次使用无限循环
					if total_runs == 1:  # 如果总运行次数为1，则跳出循环
						break
					new_path = path[:total_runs]  # 获取新的路径
					sender = new_path[0].replace("s", "h")  # 获取发送者名称
					receiver = new_path[-1].replace("s", "h")  # 获取接收者名称
					receiver_interface = receiver + "-eth0"  # 构造接收者的网络接口名称
					receiver_ip = "10.0.0." + str(receiver.replace("h", ""))  # 构造接收者的IP地址
					sender_ip = "10.0.0." + str(sender.replace("h", ""))  # 构造发送者的IP地址

					self.gen_config(receiver_interface, receiver_ip, sender_ip)  # 生成配置文件

					start_time = time.time()  # 记录开始时间
					os.system("mkdir -p experiments/" + exp_name + "/" + str(total_runs))  # 创建实验目录
					os.system("sudo pkill -9 -f recv.py")  # 终止所有recv.py进程
					os.system("sudo pkill -9 -f send.py")  # 终止所有send.py进程

					# 启动接收者
					simple_controller = "./mx {0} sudo python recv.py {1}"
					recv_job = Popen(simple_controller.format(receiver, "experiments/" + exp_name + "/" + str(total_runs) + "/" + str(self.max_bit_range)), shell=True)

					time.sleep(2)  # 暂停2秒

					# 启动发送者
					sender_ = "./mx {0} sudo python send.py"
					send_job = Popen(sender_.format(sender), shell=True)

					while True:  # 再次使用无限循环
						if send_job.poll() is None:  # 检查发送进程是否结束
							time.sleep(3)  # 暂停3秒
						else:
							break  # 如果发送进程结束，则跳出循环

					os.system("sudo pkill -9 -f recv.py")  # 终止所有recv.py进程
					self.exp_count = self.exp_count + 1  # 实验计数器加1
					print("Exp range", exp_range, "Total runs", str(self.exp_count) + "/" + str(exp_range - 1) + " Time", time.time() - start_time)  # 打印实验信息
					total_runs = total_runs - 1  # 总运行次数减1
				if total_runs == 1:  # 如果总运行次数为1
					self.all_done.add(exp_range)  # 将当前实验范围添加到完成集合中
			if len(self.all_done) == len(self.exp_ranges):  # 如果所有实验范围都完成了
				break  # 跳出最外层循环


length = int(sys.argv[1])  # 从命令行参数获取网络长度，并将其转换为整数
exp_ranges = str(sys.argv[1])  # 从命令行参数获取实验范围字符串（这里有一个错误，应该是sys.argv[2]，假设第二个参数是实验范围）
exp_ranges = [int(x) for x in exp_ranges.split(",")]  # 将实验范围字符串分割为列表，并将每个元素转换为整数

exp = Experiment(length, exp_ranges)  # 使用获取的长度和实验范围创建Experiment类的实例
exp.update_graph()  # 调用update_graph方法来更新网络图
exp.obtain_mininet_topo()  # 调用obtain_mininet_topo方法获取Mininet的拓扑信息
exp.run()  # 执行实验
