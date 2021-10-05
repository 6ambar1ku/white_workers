## [【In English】]()
##  [【日本語表示】](https://github.com/6ambar1ku/white_workers/blob/main/doc/README_JP.md)
```
           __    _ __                              __
 _      __/ /_  (_) /____     _      ______  _____/ /_____  __________
| | /| / / __ \/ / __/ _ \   | | /| / / __ \/ ___/ //_/ _ \/ ___/ ___/
| |/ |/ / / / / / /_/  __/   | |/ |/ / /_/ / /  / ,< /  __/ /  (__  )
|__/|__/_/ /_/_/\__/\___/____|__/|__/\____/_/  /_/|_|\___/_/  /____/
                       /_____/

```
一个使用VirusTotal比较ssdeep值然后呈现相似恶意软件行为的工具。 
<br></br>
<br></br>


# Description
该工具通过从数据集中的恶意软件（样本）的哈希值中检测具有高相似性的恶意软件并展示其行为、通信目的地等、来支持OSINT活动和事件响应。
<br></br>​
# VirusTotalApi v3
可以从脚本访问VriusTotal上的信息。要使用此工、您需要在VirusTotal Community上创建一个帐户并获取个人API密钥。请在本网站（[VirusTotal 社区登录](https://www.virustotal.com/gui/join-us)）上完成程序。 
<br></br>
另外、API的种类和功能如下、请根据用途进行选择。 
* Public API
    * 您可以每分钟使用一次此工具。每日使用次数上限为125次。
    * 免费使用。 
* Premium API
    * 此工具的使用没有上限。
    * 使用需要付费。（遵循 VirusTotal 指南）
<br></br>
# Settings
## API
1.在python可执行目录中创建一个".env"文件。

2.描述".env"文件中的以下内容。 
```
VT_API_KEY = {your API key}
```

## Install
* ssdeep

在 git clone [ssdeep Python Wrapper for Windows](https://github.com/MacDue/ssdeep-windows-32_64) 之后执行以下操作。 
```
(WINDOWS)> python setup.py install
```


* vtapi3
```
> pip install vtapi3
```

* dotenv
```
> pip install python-dotenv
```

* rich
```
> pip install rich
```

* pyfiglet
```
> pip install pyfiglet
```
<br></br>

# demo

<br></br>

# Usage
## Command Options
```-h```：显示可选帮助。 

```-q```：在运行时不输出 Asciiart。

```-f <file_path>```：将树结构数据输出为 txt 文件。 
<br></br>

## Program Options

### First option：
```1```：从恶意软件分析数据中输出「<font color="red">command_exectutions</font>」「<font color="blue">tags</font>」「<font color="green">verdicts</font>」。

```2```：除了1的输出数据、还输出了「<font color="yellow">proccesses</font>」。

```3```：除了1的输出数据外、还输出了「<font color="purple">dns_lookups</font>」。

```4```：除了1的输出数据外、还输出了「<font color="cyan">file_copied</font>」。

```5```：除了1的输出数据外、还输出了「<font color="magenta">ip_traffic</font>」。

```6```：输出所有1,2,3,4,5数据。 

※以上数据内容请参考[这里]()。 
<br></br>

### Second Option：
```1```：使用md5作为您要调查的恶意软件的哈希值。 

```2```：使用sha-1作为您要调查的恶意软件的哈希值。 

```3```：使用sha-256作为您要调查的恶意软件的哈希值。 



<br></br>
# License
### [MIT](https://github.com/6ambar1ku/white_workers/blob/main/LICENSE)
<br></br>
# Author
* [6ambar1ku](https://github.com/6ambar1ku) 
* [marumaru-yamayama](https://github.com/marumaru-yamayama)
* [tka12345](https://github.com/tka12345)
* [HAL-KOBA](https://github.com/HAL-Kobayashi)
* [takem0914](https://github.com/takem0914)
* [kusumotokentaro](https://github.com/kusumotokentaro)