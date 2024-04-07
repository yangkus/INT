import os  # 导入os模块，用于操作系统功能
import json  # 导入json模块，用于处理JSON数据
import sys  # 导入sys模块，用于访问与Python解释器紧密相关的变量和函数

from p4utils.utils.topology import Topology  # 从p4utils库导入Topology类，用于处理网络拓扑

class TopoAllocator:
    def __init__(self, length):
        self.length = length  # 网络长度参数
        self.b_value = 255  # 预留属性，目前未使用
        self.all_switches = set()  # 存储所有交换机的集合
        self.all_links = set()  # 存储所有连接的集合
        self.data = {}  # 存储拓扑数据的字典
        for i in range(0,length):  # 初始化交换机集合
            self.all_switches.add("s"+str(i))

        for i in range(0,length-1):  # 初始化连接集合
            self.all_links.add(("s"+str(i),"s"+str(i+1)))

        self.links = []  # 初始化链接列表

    def load_sample(self):
        with open('p4app.json_sample') as json_file:  # 加载JSON样本文件
            self.data = json.load(json_file)

        # 设置拓扑配置中的一些参数
        self.data["pcap_dump"] = False
        self.data["enable_log"] = False
        self.data["topology"]["switches"] = {}
        self.data["topology"]["hosts"] = {}

    def generate_topo(self):
        for switch in self.all_switches:  # 为每个交换机生成配置
            self.data["topology"]["switches"][switch]={}
            self.data["topology"]["switches"][switch]["cli_input"]="rules/"+switch+"-commands.txt"
            host=switch.replace("s","h")  # 根据交换机生成对应的主机
            self.data["topology"]["hosts"][host]={}
            self.links.append([switch,host,{"bw": 1000}])  # 添加交换机到主机的连接

        for link in self.all_links:  # 为每个连接生成配置
            node_1=link[0]
            node_2=link[1]
            self.links.append([node_1,node_2,{"bw":1000}])  # 添加交换机之间的连接

        self.data["topology"]["links"]=self.links  # 更新拓扑中的连接信息

        fw=open("p4app.json","w")  # 打开文件准备写入
        fw.write(json.dumps(self.data))  # 写入JSON数据
        fw.close()  # 关闭文件
 
length=int(sys.argv[1])  # 从命令行参数获取网络长度

topo = TopoAllocator(length)  # 创建TopoAllocator实例
topo.load_sample()  # 加载样本数据
topo.generate_topo()  # 生成拓扑配置
print("Run: sudo p4run --config p4app.json")  # 提示用户运行p4run命令
