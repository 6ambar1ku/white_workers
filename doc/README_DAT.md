## [【日本語表記】]()
## [【简体中文显示】]()
# Data
##  <font color="red">command_executions</font>
* shell command executions observed during the analysis of the given file.

##  <font color="blue">tags</font>
* this contains a list of labels summarizing key behavioural observations. It can be any of the following :

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| DETECT_DEBUG_ENVIRONMENT | | 
| DIRECT_CPU_CLOCK_ACCESS | | 
| LONG_SLEEPS | |
| SELF_DELETE : | file deletes itself upon execution. |
| HOSTS_MODIFIER : | local ( resolution mapping ) hosts file is modified. |
| INSTALLS_BROWSER_EXTENSION : | installs BHO, Chrome Extension, etc. |
| PASSWORD_DIALOG : | some sort of password input prompt is displayed. |
| SUDO : | promotes to admin privileges. |
| PERSISTENCE : | employs persistence mechanisms to survive reboots. |
| SENDS_SMS | |
| CHECKS_GPS | |
| FTP_COMMUNICATION | |
| SSH_COMMUNICATION | |
| TELNET_COMMUNICATION | |
| SMTP_COMMUNICATION | |
| MYSQL_COMMUNICAION | |
| IRC_COMMUNICATION | |
| SUSPICIOUS_DNS : | possible DGA ( Domain generation algorithm ). |
| SUSPICIOUS_UDP : | high counts of distinct UDP connections, this may often reveal P2P. |
| BIG_UPSTREAM : | large outgoing network traffic. |
| TUNNELING : |some sort of network tunneling observed, e.g. VPN. |
| CRYPTO : | makes use of crypto related APIs. |
| TELEPHONY : | makes use of telephony related APIs. |
| RUNTIME_MODULES : | dynamically loads DLLs or additional components. |
| REFLECTION : | performs reflection calls. |
|              |                                                       | 


##  <font color="green">verdicts</font>
* This contains a list of maliciousness classifications for the file under study based on its behaviour. It is a list of strings, that can contain any of the following :

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| CLEAN : | clean, whitelisted or undetected. |
| MALWARE : | should be detected as malware. |
| GREYWARE : | PUA, PUP (possibly unwanted program). |
| RANSOM : | Ransom or crypter. |
| PHISHING : | Tries to phish the user or deceive him to steel his credentials. |
| BANKER : | banking trojan malware. |
| ADWARE : | displays unwanted advertisements. |
| EXPLOIT : | contains or runs an exploit. |
| EVADER : | contains logic to evade analysis. |
| RAT : | remote access trojan, may listen for inbound connections. |
| TROJAN : | trojan or bot. |
| SPREADER : | spreads to USB, other drives, network, etc. Work-like functionality. |
|              |                                                       | 

##  <font color="yellow">proccesses</font>
* This contains a list of created processes by a given file but do not show  processes created by a given process( children ). It is a list of dictionaries, each one cpntains the following fields :

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| proccess_name :   | proccess name.                              | 
| proccess_id : | ID of the proccess | 
|              |                                                       | 

##  <font color="purple">dns_lookups</font>
* This contains a list of domain name resolutions performed by a given file. It is a list of dictionaries, each one containing the following fields :

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| hostname :   | hostname of DNS query.                                | 
| resolved_ips : | all resolved IP addresses, may be empty on NX domain. | 
|              |                                                       | 

##  <font color="cyan">files_copied</font>
* This contains a list of files that were copied from one location to another. It is a list, every item of the list containing the following fields :

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| destination : | full path of the destination file.                   | 
| source : | full path of the source file.                             | 
|              |                                                       | 

##  <font color="magenta">ip_trafic</font>
* This contains a list of outgoing connections seen during the execution of a given file. It is a list, every item on the list containing the following fields :

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| transport_layer_protocol : | One of ( ICMP, IGMP, TCP, UDP, ESP, AH, L2TP, SCTP ).                       | 
| destination_ip : | IP address.                                       | 
| destination_port : | Port number.                                    | 
