## [【In English】]()
## [【日本語表記】]()
# Data
##  <font color="red">command_executions</font>
*　在分析指定文件期间观察到的 shell 命令执行列表。

##  <font color="blue">tags</font>
* 用关键行为标记。每个标签的内容是以下 25 种类型。

|              |                                                       |
| ------------ | ----------------------------------------------------- |
| DETECT_DEBUG_ENVIRONMENT | 调试环境检测 |
| DIRECT_CPU_CLOCK_ACCESS | 访问 CPU 时钟 |
| LONG_SLEEPS | 长时间睡眠 |
| SELF_DELETE: | 执行文件时删除自身 |
| HOSTS_MODIFIER: | 本地主机文件已修改 |
| INSTALLS_BROWSER_EXTENSION: | 安装 BHO、Chrome 扩展等 |
| PASSWORD_DIALOG: | 提示输入某种密码 |
| SUDO: | 提升为管理员权限 |
| PERSISTENCE：| 采用持久性机制以在重启后继续存在 |
| SENDS_SMS | 发送短信 |
| CHECKS_GPS | 检查 GPS |
| FTP_COMMUNICATION | 使用 FTP |
| SSH_COMMUNICATION | 使用 SSH |
| TELNET_COMMUNICATION | 使用 TELNET |
| SMTP_COMMUNICATION | 使用 SMTP |
| MYSQL_COMMUNICAION | 使用 MYSQL |
| IRC_COMMUNICATION | 使用 IRC |
| SUSPICIOUS_DNS: | 可疑 DGA（域生成算法）|
| SUSPICIOUS_UDP: | 可疑的 UDP 通信（经常暴露 P2P） |
| BIG_UPSTREAM: | 大量网络流量上升 |
| TUNNELING：| 观察到某种网络隧道，例如 VPN |
| CRYPTO：| 使用与加密相关的 API |
| TELEPHONY： | 使用无线 API |
| RUNTIME_MODULES: | 动态加载 DLL 或附加组件 |
| REFLECTION： | 进行反射调用 |
| | |


##  <font color="green">verdicts</font>
* 分类基于目标文件的行为。每个元素的内容是以下 12 种类型。

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| CLEAN : | 列入白名单或未被发现 |
| MALWARE : | 检测为恶意软件 |
| GREYWARE : | 不需要的应用程序或不需要的程序 |
| RANSOM : | 勒索软件或加密 |
| PHISHING : | 网络钓鱼用户或诱骗用户窃取凭据 |
| BANKER : | 银行木马恶意软件 |
| ADWARE : | 显示不需要的广告 |
| EXPLOIT : | 漏洞利用被包含或正在运行 |
| EVADER : | 包含避免分析的逻辑 |
| RAT : | 远程访问恶意软件可以监听入站通信 |
| TROJAN : | 特洛伊木马或机器人 |
| SPREADER : | 传播到 USB、其他驱动器、网络等 |
|              |                                                       | 

##  <font color="yellow">proccesses</font>
* 在执行指定文件期间创建的进程列表。但是，仅列出以递归方式构建的可以构建流程树的已创建流程。项目如下。

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| proccess_name :   | 进程名称                             | 
| proccess_id : | 进程ID | 
|              |                                                       | 

##  <font color="purple">dns_lookups</font>
*  由特定文件执行的域名解析列表。列表为字典类型，每个字典包含以下字段。

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| hostname :   | DNS 查询主机名                               | 
| resolved_ips : | 所有解析的IP地址。NX域中可能为空 | 
|              |                                                       | 

##  <font color="cyan">files_copied</font>
* 从一个位置复制到另一个位置的文件列表。该列表是列表类型，列表中的所有项目都包含以下字段。

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| destination : | 目标文件的完整路径　| 
| source : |  源文件的完整路径 | 
|              |                                                       | 

##  <font color="magenta">ip_trafic</font>
* 在特定文件运行时可以看到的传出连接列表。 lister 是一个列表类型，列表中的每一项都包含以下字段。

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| transport_layer_protocol : | ICMP, IGMP, TCP, UDP, ESP, AH, L2TP, SCTP之一. | 
| destination_ip : |  IP 地址   | 
| destination_port : | 端口号 | 
|              |                                                       | 
