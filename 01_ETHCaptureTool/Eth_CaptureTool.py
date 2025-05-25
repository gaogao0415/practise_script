import ctypes as ct 
import time
import libpcap as pcap
from datetime import datetime, timedelta 
from pathlib import Path 
import tkinter as tk 
from tkinter import ttk, filedialog, messagebox
import threading 
import os
 
class PacketCaptureApp:
    def __init__(self, root):
        self.root  = root
        self.root.title(" 以太网数据包捕获工具")
        
        # 初始化变量 
        self.device  = None
        self.handle  = None
        self.fpcap  = None
        self.capture_running  = False 
        self.pause_flag  = False 
        self.capture_count  = 0  # 新增：捕获次数计数器
        self.UDPPacketNum = 0
        self.total_bytes  = 0
        self.log_file_name  = ""
        self.device_map  = {}
        self.capture_folder  = "captured_packets"
        self.log_history  = []
        
        # 创建GUI界面 
        self.create_widgets() 
        self.load_network_interfaces() 
        self.create_author_label() 
        self.create_version_label() 
    
    def create_author_label(self):
        author_frame = ttk.Frame(self.root) 
        author_frame.grid(row=1,  column=0, sticky=tk.SE, padx=5, pady=5)
        ttk.Label(
            author_frame, 
            text="Author: gao.gao",  
            font=('Arial', 8),
            foreground="gray"
        ).pack(side=tk.RIGHT)
    
    def create_version_label(self):
        version_frame = ttk.Frame(self.root) 
        version_frame.grid(row=1,  column=0, sticky=tk.SW, padx=5, pady=5)
        ttk.Label(
            version_frame,
            text="Version:1.0.2",
            font=('Arial', 8),
            foreground="gray"
        ).pack(side=tk.LEFT)
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.root,  padding="10")
        main_frame.grid(row=0,  column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 网卡选择
        ttk.Label(main_frame, text="选择网卡:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.interface_combobox  = ttk.Combobox(main_frame, state="readonly")
        self.interface_combobox.grid(row=0,  column=1, sticky=tk.EW, pady=5)
        
        # 捕获时间设置 
        ttk.Label(main_frame, text="捕获时间(分钟):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.capture_time_entry  = ttk.Entry(main_frame)
        self.capture_time_entry.insert(0,  "5")
        self.capture_time_entry.grid(row=1,  column=1, sticky=tk.EW, pady=5)
        
        # 存储路径
        ttk.Label(main_frame, text="存储路径:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.path_entry  = ttk.Entry(main_frame)
        self.path_entry.insert(0,  self.capture_folder) 
        self.path_entry.grid(row=2,  column=1, sticky=tk.EW, pady=5)
        ttk.Button(main_frame, text="浏览...", command=self.select_storage_path).grid(row=2,  column=2, pady=5)
        
        # 控制按钮 
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3,  column=0, columnspan=3, pady=10)
        
        self.start_button  = ttk.Button(button_frame, text="开始捕获", command=self.start_capture) 
        self.start_button.pack(side=tk.LEFT,  padx=5)
        
        self.pause_button  = ttk.Button(button_frame, text="暂停捕获", command=self.pause_capture,  state=tk.DISABLED)
        self.pause_button.pack(side=tk.LEFT,  padx=5)
        
        self.stop_button  = ttk.Button(button_frame, text="停止捕获", command=self.stop_capture,  state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT,  padx=5)
        
        # 状态栏 
        self.status_var  = tk.StringVar()
        self.status_var.set(" 就绪")
        self.status_label  = ttk.Label(
            main_frame, 
            textvariable=self.status_var,  
            relief=tk.SUNKEN,
            wraplength=600,
            anchor=tk.W,
            padding=(5, 5)
        )
        self.status_label.grid(row=4,  column=0, columnspan=3, sticky=tk.EW, pady=5)
        
        # 网格配置
        main_frame.columnconfigure(1,  weight=1)
        self.root.columnconfigure(0,  weight=1)
        self.root.rowconfigure(0,  weight=1)
        self.root.rowconfigure(1,  weight=1)
 
    def load_network_interfaces(self):
        errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE  + 1)
        alldevices = ct.POINTER(pcap.pcap_if_t)() 
        pcap.findalldevs(ct.byref(alldevices),  errbuf)
        
        interfaces = []
        while alldevices and alldevices.contents: 
            if alldevices.contents.description: 
                display_name = alldevices.contents.description.decode() 
                if_name = alldevices.contents.name.decode() 
                interfaces.append(display_name) 
                self.device_map[display_name]  = if_name
            alldevices = alldevices.contents.next 
        
        self.interface_combobox['values']  = interfaces 
        if interfaces:
            self.interface_combobox.current(0) 
 
    def select_storage_path(self):
        folder_selected = filedialog.askdirectory(title=" 选择数据包存储路径")
        if folder_selected:
            self.capture_folder  = folder_selected
            self.path_entry.delete(0,  tk.END)
            self.path_entry.insert(0,  folder_selected)
 
    def start_capture(self):
        if not self.interface_combobox.get(): 
            messagebox.showerror(" 错误", "请选择网卡接口")
            return 
        
        try:
            self.capture_period  = int(self.capture_time_entry.get()) 
            if self.capture_period  <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror(" 错误", "请输入有效的捕获时间(正整数)")
            return
        
        # 准备新的捕获会话 
        self.capture_count  += 1 
        Path(self.capture_folder).mkdir(parents=True,  exist_ok=True)
        self.log_file_name  = os.path.join(self.capture_folder,  f"ETH_capture_{self.capture_count}.log") 
        
        # 清空历史记录
        self.log_history  = []
        self.UDPPacketNum = 0 
        self.total_bytes  = 0
        self.pause_flag  = False
        
        display_name = self.interface_combobox.get() 
        self.device  = self.device_map[display_name].encode() 
        
        errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE  + 1)
        self.handle  = pcap.open_live(self.device,  1518, 16, 100, errbuf)
        
        start_time_str = time.strftime("%Y%m%d%H%M%S",  time.localtime()) 
        pcap_filename = os.path.join(self.capture_folder,  f"ETHCaptureData_{start_time_str}.pcap")
        self.fpcap  = pcap.dump_open(self.handle,  pcap_filename.encode()) 
        self.fpcapUbyte  = ct.cast(self.fpcap,  ct.POINTER(ct.c_ubyte))
        self.pheader  = pcap.pkthdr() 
        pcap.setbuff(self.handle,  64 * 1024 * 1024)
        
        self.capture_running  = True
        self.start_button.config(state=tk.DISABLED) 
        self.pause_button.config(state=tk.NORMAL,  text="暂停捕获")
        self.stop_button.config(state=tk.NORMAL) 
        
        # 添加开始日志 
        start_msg = f"=== 第{self.capture_count} 次捕获开始: {start_time_str} ==="
        self.log_history.append(start_msg) 
        self.update_status(start_msg) 
        
        self.capture_thread  = threading.Thread(target=self.run_capture,  daemon=True)
        self.capture_thread.start() 
 
    def pause_capture(self):
        if self.pause_flag: 
            # 恢复捕获 
            self.pause_flag  = False 
            self.pause_button.config(text=" 暂停捕获")
            resume_msg = f"恢复捕获: {time.strftime('%Y%m%d%H%M%S',  time.localtime())}" 
            self.log_history.append(resume_msg) 
            self.update_status(resume_msg) 
        else:
            # 暂停捕获
            self.pause_flag  = True
            self.pause_button.config(text=" 继续捕获")
            pause_msg = f"暂停捕获: {time.strftime('%Y%m%d%H%M%S',  time.localtime())}" 
            self.log_history.append(pause_msg) 
            self.update_status(pause_msg) 
 
    def run_capture(self):
        one_minute = timedelta(minutes=self.capture_period) 
        
        while self.capture_running: 
            if self.pause_flag: 
                time.sleep(0.1)   # 暂停时降低CPU占用 
                continue
                
            start_time_str = time.strftime("%Y%m%d%H%M%S",  time.localtime()) 
            self.save_timestamp_log(self.UDPPacketNum,  start_time_str)
            
            if self.UDPPacketNum > 0:
                self.packet_cut(self.UDPPacketNum,  start_time_str)
            
            start_time = datetime.strptime(start_time_str,  "%Y%m%d%H%M%S")
            bytes_captured = self.save_pcap_data(start_time,  one_minute)
            self.total_bytes  += bytes_captured
            
            end_time_str = time.strftime("%Y%m%d%H%M%S",  time.localtime()) 
            self.UDPPacketNum += 1
            
            # 更新状态和日志
            status_msg = (
                f"当前捕获: Packet [{self.UDPPacketNum}] | "
                f"时间: {start_time_str} - {end_time_str} | "
                f"本次捕获: {bytes_captured/1024:.2f} KB | "
                f"累计: {self.UDPPacketNum} Packets / {self.total_bytes/1024:.2f}  KB"
            )
            log_msg = (
                f"Packet [{self.UDPPacketNum}] | "
                f"开始: {start_time_str} | 结束: {end_time_str} | "
                f"大小: {bytes_captured/1024:.2f} KB"
            )
            
            self.log_history.append(log_msg) 
            self.root.after(0,  self.update_status,  status_msg)
        
        self.root.after(0,  self.capture_finished) 
 
    def save_pcap_data(self, start_time, capture_time):
        bytes_captured = 0
        while self.capture_running  and not self.pause_flag: 
            current_time = datetime.now() 
            packet = pcap.next(self.handle,  self.pheader) 
            if not packet:
                continue
            
            bytes_captured += self.pheader.len  
            pcap.dump(self.fpcapUbyte,  self.pheader,  packet)
            
            if current_time - start_time >= capture_time:
                break
        
        return bytes_captured 
 
    def packet_cut(self, packet_num, current_datetime_str):
        pcap_filename = os.path.join(self.capture_folder,  f"ETHCaptureData_{current_datetime_str}.pcap")
        pcap.dump_close(self.fpcap) 
        self.fpcap  = pcap.dump_open(self.handle,  pcap_filename.encode()) 
        return pcap_filename 
 
    def save_timestamp_log(self, packet_num, current_datetime_str):
        mode = "w" if packet_num == 0 else "a"
        with open(self.log_file_name,  mode) as log_file:
            log_line = f"Packet {packet_num} Start: {current_datetime_str}"
            log_file.write(log_line  + "\n")
            self.log_history.append(log_line) 
        
        self.root.after(0,  self.update_status,  "\n".join(self.log_history[-5:])) 
 
    def update_status(self, message):
        self.status_var.set(message) 
 
    def stop_capture(self):
        self.capture_running  = False 
        self.pause_flag  = False 
        stop_msg = f"停止捕获: {time.strftime('%Y%m%d%H%M%S',  time.localtime())}" 
        self.log_history.append(stop_msg) 
        self.update_status(stop_msg) 
        self.pause_button.config(state=tk.DISABLED) 
        self.stop_button.config(state=tk.DISABLED)
         
    def capture_finished(self):
        if self.handle: 
            pcap.close(self.handle) 
            self.handle  = None 
    
        if self.fpcap: 
            pcap.dump_flush(self.fpcap) 
            pcap.dump_close(self.fpcap) 
            self.fpcap  = None 
    
        end_time = time.strftime("%Y%m%d%H%M%S",  time.localtime()) 
    
    # 安全获取开始时间，防止空列表 
        start_time = "N/A"
        if self.log_history  and len(self.log_history)  > 0:
            try:
                start_time = self.log_history[0].split(':  ')[1]
            except (IndexError, AttributeError):
                start_time = self.log_history[0]  if self.log_history  else "N/A"
    
        final_msg = (
            f"=== 第{self.capture_count} 次捕获完成 ===\n"
            f"总包数: {self.UDPPacketNum}\n"
            f"总数据量: {self.total_bytes/1024:.2f}  KB\n"
            f"开始时间: {start_time}\n"
            f"结束时间: {end_time}"
        )
    
        self.log_history.extend(final_msg.split("\n")) 
        self.update_status("\n".join(self.log_history[-10:])) 
    
    # 保存完整日志到文件 
        if self.log_file_name:   # 确保日志文件名存在 
            with open(self.log_file_name,  'a') as log_file:
                log_file.write("\n".join(self.log_history)  + "\n")
    
        self.start_button.config(state=tk.NORMAL) 
        self.pause_button.config(state=tk.DISABLED,  text="暂停捕获")
        self.stop_button.config(state=tk.DISABLED) 
 
    def on_closing(self):
        if self.capture_running: 
            self.stop_capture() 
            self.capture_thread.join(timeout=1) 
        
        if self.handle: 
            pcap.close(self.handle) 
        
        if self.fpcap: 
            pcap.dump_flush(self.fpcap) 
            pcap.dump_close(self.fpcap) 
        
        self.root.destroy() 
 
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketCaptureApp(root)
    root.protocol("WM_DELETE_WINDOW",  app.on_closing) 
    root.mainloop() 