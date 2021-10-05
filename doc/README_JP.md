## [【In English】](https://github.com/6ambar1ku/white_workers/blob/main/README.md)
##  [【简体中文显示】](https://github.com/6ambar1ku/white_workers/blob/main/doc/README_CH.md)
```
           __    _ __                              __
 _      __/ /_  (_) /____     _      ______  _____/ /_____  __________
| | /| / / __ \/ / __/ _ \   | | /| / / __ \/ ___/ //_/ _ \/ ___/ ___/
| |/ |/ / / / / / /_/  __/   | |/ |/ / /_/ / /  / ,< /  __/ /  (__  )
|__/|__/_/ /_/_/\__/\___/____|__/|__/\____/_/  /_/|_|\___/_/  /____/
                       /_____/

```
Virus Totalを用いて、ssdeepの値を比較後に類似マルウェアのふるまいを提示するツール
<br></br>
<br></br>


# Description
本ツールはマルウェア（検体）のハッシュ値から類似性の高いマルウェアをデータセットから検出し、それらの挙動、通信先等を提示することで、OSINT活動、インシデントレスポンスを支援します。
<br></br>​
# VirusTotalApi v3
VriusTotal上の情報にスクリプトからのアクセスが可能になります。なお、本ツールを使用するに当たりまして、VirusTotal Communityにてアカウント作成および、パーソナルAPIキーの取得が必要です。当サイト([VirusTotal Communityログイン](https://www.virustotal.com/gui/join-us))にて手続きをお願いいたします。
<br></br>
また、APIの種類および機能については以下の通りですので、使用用途に合わせた選択をして下さい。
* Public API
    * 本ツールを1分間に1回使用できます。1日の使用上限は125回までです。
    * 無料で使用できます。
* Premium API
    * 本ツールの使用上限がなくなります。
    * 使用は有料です。(VirusTotalの案内に従ってください)
<br></br>
# Settings
## API
1. pythonの実行ファイルのディレクトリに.envファイルを作成します。
2. .envファイル内に以下の内容を記述します。
```
VT_API_KEY = {your API key}
```

## Install
* ssdeep

[ssdeep Python Wrapper for Windows](https://github.com/MacDue/ssdeep-windows-32_64)
をgit clone後に以下を実行
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
```-h```：オプションのヘルプを表示します。

```-q```：実行時にAsciiartの出力をしません。

```-f <file_path>```：ツリー構造のデータをtxtファイルで出力します。
<br></br>

## Program Options

### First option：
```1```：マルウェア解析データのうち、「<font color="red">command_exectutions</font>」「<font color="blue">tags</font>」「<font color="green">verdicts</font>」を出力します。

```2```：1の出力データに加えて、「<font color="yellow">proccesses</font>」を出力します。

```3```：1の出力データに加えて、「<font color="purple">dns_lookups</font>」を出力します。

```4```：1の出力データに加えて、「<font color="cyan">file_copied</font>」を出力します。

```5```：1の出力データに加えて、「<font color="magenta">ip_traffic</font>」を出力します。

```6```：1,2,3,4,5のデータ全てを出力します。

※なお、上記データの内容につきましては[こちら](https://github.com/6ambar1ku/white_workers/blob/main/doc/README_DAT_JP.md)を参照してください。
<br></br>

### Second Option：
```1```：調査したいマルウェアのhash値にmd5を使用します。

```2```：調査したいマルウェアのhash値にsha-1を使用します。

```3```：調査したいマルウェアのhash値にsha-256を使用します。



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