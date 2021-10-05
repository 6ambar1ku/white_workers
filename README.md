## [【日本語表記】](https://github.com/6ambar1ku/white_workers/blob/main/doc/README_JP.md)
##  [【简体中文显示】](https://github.com/6ambar1ku/white_workers/blob/main/doc/README_CH.md)
```
           __    _ __                              __
 _      __/ /_  (_) /____     _      ______  _____/ /_____  __________
| | /| / / __ \/ / __/ _ \   | | /| / / __ \/ ___/ //_/ _ \/ ___/ ___/
| |/ |/ / / / / / /_/  __/   | |/ |/ / /_/ / /  / ,< /  __/ /  (__  )
|__/|__/_/ /_/_/\__/\___/____|__/|__/\____/_/  /_/|_|\___/_/  /____/
                       /_____/

```
White_workers present similar malware behavior ( by using VirusTotal ) after comparing ssdeep values.
<br></br>
<br></br>


# Description
White_workers supports OSINT activities and incident response by detecting malware with high similarity from the hash value of malware from the dataset and presenting their behavior, started proccesses, etc. 
<br></br>​
# VirusTotalApi v3
If you use VirusTotalApi v3, the information on VriusTotal can be accessed from the script. To use this tool, you need to create an account and obtain a personal API key on VirusTotal Community. Please complete the procedure on this site ([VirusTotal Community Login](https://www.virustotal.com/gui/join-us)). 
<br></br>
In addition, the types and functions of the API are as follows, so please select the one you want to use. 
* Public API
    * You can use this tool once a minute. The daily usage limit is 125 times.
    * Free to use.
* Premium API
    * No upper limit to the usage of this tool.
    * There is a charge for use. (Follow VirusTotal guidance) 
<br></br>
# Settings
## API
1. Create an ".env" file in the python executable directory. 
2. Describe the following contents in the ".env" file. 
```
VT_API_KEY = {your API key}
```

## Install
* ssdeep

Please run as follows after git clone 
[ssdeep Python Wrapper for Windows](https://github.com/MacDue/ssdeep-windows-32_64).
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
![demo](https://raw.githubusercontent.com/wiki/6ambar1ku/white_workers/demo/white_workers.gif)

<br></br>

# Usage
## Command Options
```-h```：Display optional help.

```-q```：Does not output Ascii art at runtime.

```-f <file_path>```：Outputs tree structure data as a txt file.
<br></br>

## Program Options

### First option：
```1```：Outputs 「<font color="red">command_executions</font>」 「<font color="blue">tags</font>」 and 「<font color="green">verdicts</font>」 from malware analysis data.

```2```：Outputs「<font color="yellow">proccesses</font>」 from malware analysis data.

```3```：Outputs「<font color="purple">dns_lookups</font>」 from malware analysis data.

```4```：Outputs「<font color="cyan">file_copied</font>」 from malware analysis data.

```5```：Outputs「<font color="magenta">ip_traffic</font>」 from malware analysis data.

```6```：Outputs all 1,2,3,4,5 data. 

※ Please refer to [here](https://github.com/6ambar1ku/white_workers/blob/main/doc/README_DAT.md) for the contents of the above data. 
<br></br>

### Second Option：
```1```：Use md5 for the hash value of the malware you want to investigate. 

```2```：Use sha-1 for the hash value of the malware you want to investigate. 

```3```：Use sha-256 for the hash value of the malware you want to investigate. 



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