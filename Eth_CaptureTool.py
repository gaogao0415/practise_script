import tkinter as tk
from tkinter import ttk, messagebox
import scapy.all as scapy
from scapy.arch import get_if_list
import pandas as pd
import matplotlib.pyplot as plt
from threading import Thread
import time
import re


class EthernetCaptureApp:
    def __init__(self, root):
        self.root = root
        self.root.title(" 以太网数据包采集工具")
        self.root.geometry("600x500")

        # 捕获控制变量
        self.is_capturing = False
        self.capture_thread = None
        self.packets = []

        # 网卡名称映射表（中文显示名:实际接口名）
        self.interface_map = {}

        # 创建界面元素
        self.create_widgets()

        # 初始刷新网卡列表
        self.refresh_interfaces()

    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 网卡选择部分
        interface_frame = ttk.LabelFrame(main_frame, text="网卡选择", padding="10")
        interface_frame.pack(fill=tk.X, pady=5)

        ttk.Label(interface_frame, text="选择网卡:").pack(anchor=tk.W)

        self.interface_var = tk.StringVar()
        self.interface_combobox = ttk.Combobox(
            interface_frame,
            textvariable=self.interface_var,
            state="readonly",
            width=50
        )
        self.interface_combobox.pack(fill=tk.X, pady=5)

        # 刷新网卡列表按钮
        ttk.Button(
            interface_frame,
            text="刷新网卡列表",
            command=self.refresh_interfaces
        ).pack(pady=5)

        # 捕获设置部分
        settings_frame = ttk.LabelFrame(main_frame, text="捕获设置", padding="10")
        settings_frame.pack(fill=tk.X, pady=5)

        ttk.Label(settings_frame, text="单包捕获时间(秒):").grid(row=0, column=0, sticky=tk.W)
        self.capture_time_var = tk.DoubleVar(value=1.0)
        ttk.Entry(
            settings_frame,
            textvariable=self.capture_time_var,
            width=10
        ).grid(row=0, column=1, sticky=tk.W, padx=5)

        # 捕获按钮
        self.capture_button = ttk.Button(
            main_frame,
            text="开始捕获",
            command=self.toggle_capture,
            style="Accent.TButton"
        )
        self.capture_button.pack(pady=10)

        # 数据包统计显示
        stats_frame = ttk.LabelFrame(main_frame, text="捕获统计", padding="10")
        stats_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.stats_text = tk.Text(
            stats_frame,
            height=10,
            state=tk.DISABLED,
            wrap=tk.WORD
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True)

        # 滚动条
        scrollbar = ttk.Scrollbar(stats_frame, command=self.stats_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.stats_text.config(yscrollcommand=scrollbar.set)

        # 分析按钮
        ttk.Button(
            main_frame,
            text="分析数据包",
            command=self.analyze_packets
        ).pack(pady=5)

        # 样式配置
        self.root.style = ttk.Style()
        self.root.style.configure("Accent.TButton", font=('Microsoft YaHei', 10, 'bold'))

    def translate_interface_name(self, if_name):
        """将网卡接口名转换为更友好的中文显示名"""
        # 常见网卡类型映射
        translations = {
            'eth': '以太网',
            'ens': '以太网',
            'enp': '以太网',
            'wlan': '无线网',
            'wlp': '无线网',
            'lo': '本地回环',
            'veth': '虚拟以太网',
            'docker': 'Docker网络',
            'br-': '网桥',
            'tun': '隧道',
            'tap': '虚拟网卡'
        }

        # 尝试匹配已知前缀
        for prefix, name in translations.items():
            if if_name.startswith(prefix):
                # 提取数字部分（如果有）
                numbers = re.findall(r'\d+', if_name[len(prefix):])
                if numbers:
                    return f"{name}适配器 {numbers[0]}"
                return f"{name}适配器"

        # 默认返回原名称
        return if_name

    def refresh_interfaces(self):
        """刷新网卡列表并显示中文名称"""
        interfaces = get_if_list()
        self.interface_map = {}
        display_names = []

        for iface in interfaces:
            display_name = self.translate_interface_name(iface)
            self.interface_map[display_name] = iface
            display_names.append(display_name)

        self.interface_combobox['values'] = display_names
        if display_names:
            self.interface_var.set(display_names[0])

    def get_selected_interface(self):
        """获取当前选中的实际网卡接口名"""
        display_name = self.interface_var.get()
        return self.interface_map.get(display_name, display_name)

    def toggle_capture(self):
        if not self.is_capturing:
            # 开始捕获
            interface = self.get_selected_interface()
            if not interface:
                messagebox.showerror(" 错误", "请选择网卡")
                return

            try:
                capture_time = float(self.capture_time_var.get())
                if capture_time <= 0:
                    raise ValueError
            except ValueError:
                messagebox.showerror(" 错误", "请输入有效的捕获时间(正数)")
                return

            self.is_capturing = True
            self.capture_button.config(text=" 停止捕获")
            self.packets = []  # 清空之前的数据

            # 在新线程中开始捕获
            self.capture_thread = Thread(
                target=self.capture_packets,
                args=(interface, capture_time),
                daemon=True
            )
            self.capture_thread.start()
        else:
            # 停止捕获
            self.is_capturing = False
            self.capture_button.config(text=" 开始捕获")

    def capture_packets(self, interface, capture_time):
        start_time = time.time()

        def packet_callback(packet):
            if not self.is_capturing:
                return False  # 停止捕获

            self.packets.append(packet)
            # 更新UI需要在主线程中执行
            self.root.after(0, self.update_stats)
            return True

            # 使用scapy的sniff函数捕获数据包

        scapy.sniff(
            iface=interface,
            prn=packet_callback,
            timeout=capture_time,
            store=False
        )

        # 捕获完成后更新状态
        self.is_capturing = False
        self.root.after(0, lambda: self.capture_button.config(text=" 开始捕获"))
        self.root.after(0, self.update_stats)

    def update_stats(self):
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)

        if not self.packets:
            self.stats_text.insert(tk.END, "没有捕获到数据包")
        else:
            self.stats_text.insert(tk.END, f"已捕获 {len(self.packets)}  个数据包\n\n")

            # 简单统计不同类型协议的数量
            protocol_counts = {}
            for pkt in self.packets:
                if scapy.IP in pkt:
                    proto = pkt[scapy.IP].get_field('proto').i2repr(pkt[scapy.IP], pkt[scapy.IP].proto)
                elif scapy.IPv6 in pkt:
                    proto = pkt[scapy.IPv6].nh
                else:
                    proto = pkt.name

                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

                # 按数量排序
            sorted_protos = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)

            for proto, count in sorted_protos:
                self.stats_text.insert(tk.END, f"{proto}: {count} 个\n")

        self.stats_text.config(state=tk.DISABLED)

    def analyze_packets(self):
        if not self.packets:
            messagebox.showinfo(" 提示", "没有数据包可供分析")
            return

            # 创建DataFrame用于分析
        data = []
        for pkt in self.packets:
            try:
                if scapy.IP in pkt:
                    src = pkt[scapy.IP].src
                    dst = pkt[scapy.IP].dst
                    proto = pkt[scapy.IP].get_field('proto').i2repr(pkt[scapy.IP], pkt[scapy.IP].proto)
                    length = len(pkt)
                    data.append([src, dst, proto, length])
                elif scapy.IPv6 in pkt:
                    src = pkt[scapy.IPv6].src
                    dst = pkt[scapy.IPv6].dst
                    proto = pkt[scapy.IPv6].nh
                    length = len(pkt)
                    data.append([src, dst, f"IPv6-{proto}", length])
            except:
                continue

        if not data:
            messagebox.showinfo(" 提示", "没有IP数据包可供分析")
            return

        df = pd.DataFrame(data, columns=['源地址', '目的地址', '协议', '长度'])

        # 显示统计信息
        print("\n数据包统计信息:")
        print(df.describe())

        # 按协议分组统计
        protocol_stats = df.groupby(' 协议').agg({'长度': ['count', 'mean', 'sum']})
        print("\n按协议统计:")
        print(protocol_stats)

        # 绘制图表
        plt.rcParams['font.sans-serif'] = ['Microsoft YaHei']  # 设置中文字体
        plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题

        plt.figure(figsize=(12, 6))

        # 协议分布饼图
        plt.subplot(1, 2, 1)
        protocol_counts = df['协议'].value_counts()
        protocol_counts.plot.pie(
            autopct='%1.1f%%',
            title='协议分布',
            ylabel='',
            startangle=90
        )

        # 数据包长度分布直方图
        plt.subplot(1, 2, 2)
        df['长度'].plot.hist(
            bins=20,
            title='数据包长度分布',
            edgecolor='black'
        )
        plt.xlabel(' 字节数')

        plt.tight_layout()
        plt.show()


if __name__ == "__main__":
    root = tk.Tk()
    try:
        # Windows系统下设置高DPI
        from ctypes import windll

        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass

    app = EthernetCaptureApp(root)
    root.mainloop()
