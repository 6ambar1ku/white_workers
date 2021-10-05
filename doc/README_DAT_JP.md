## [【日本語表記】](https://github.com/6ambar1ku/white_workers/blob/main/doc/README_DAT_JP.md)
## [【简体中文显示】](https://github.com/6ambar1ku/white_workers/blob/main/doc/README_DAT_CH.md)
# Data
##  <font color="red">command_executions</font>
* 指定されたファイルの分析中に観察されたシェルコマンド実行のリストです。

##  <font color="blue">tags</font>
* 主要な振る舞いでタグ付けを行っています。各々のタグの内容は以下の25通りです。

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| DETECT_DEBUG_ENVIRONMENT | デバッグ環境の検出 | 
| DIRECT_CPU_CLOCK_ACCESS | CPUクロックへのアクセス| 
| LONG_SLEEPS | ロングスリープ |
| SELF_DELETE : | ファイル実行時に自分自身を削除 |
| HOSTS_MODIFIER : | ローカルhostsファイルが変更された|
| INSTALLS_BROWSER_EXTENSION : | BHO、Chrome拡張機能などをインストール |
| PASSWORD_DIALOG : | ある種のパスワード入力プロンプトを表示 |
| SUDO : | 管理者権限に昇格 |
| PERSISTENCE : | 再起動後も存続するために永続性メカニズムを採用 |
| SENDS_SMS | SMSを送信　|
| CHECKS_GPS | GPSを確認　|
| FTP_COMMUNICATION | FTPを使用 |
| SSH_COMMUNICATION |  SSHを使用|
| TELNET_COMMUNICATION | TELNETを使用 |
| SMTP_COMMUNICATION |SMTPを使用 |
| MYSQL_COMMUNICAION | MYSQLを使用 |
| IRC_COMMUNICATION | IRCを使用 |
| SUSPICIOUS_DNS : | 疑わしいDGA(ドメイン生成アルゴリズム) |
| SUSPICIOUS_UDP : | 疑わしいUDP通信(これによりP2Pが明らかになることがよくある) |
| BIG_UPSTREAM : | 大規模なネットワークトラフィックの上昇 |
| TUNNELING : | VPNなど、ある種のネットワークトンネリングが観察 |
| CRYPTO : | 暗号関連のAPIを利用 |
| TELEPHONY : | 無線関連のAPIを利用 |
| RUNTIME_MODULES : | DLLまたは追加コンポーネントを動的にロード |
| REFLECTION : | リフレクション呼び出しを実行 |
|              |                                                       | 


##  <font color="green">verdicts</font>
* 対象となるファイルの挙動に基づいて分類しています。各々の要素の内容は以下の12通りです。


|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| CLEAN : | ホワイトリストに登録されている、または検出されていない |
| MALWARE : | マルウェアとして検出 |
| GREYWARE : | 望ましくないアプリケーションもしくは、望ましくないプログラム |
| RANSOM : | ランサムウェアもしくは、暗号化 |
| PHISHING : | ユーザーをフィッシングするか、ユーザーをだまして資格情報を窃取 |
| BANKER : | バンキング型トロイの木馬マルウェア |
| ADWARE : | 不要な広告を表示 |
| EXPLOIT : | エクスプロイトが含まれている、または実行されている |
| EVADER : | 分析を回避するロジックが含まれる |
| RAT : | リモートアクセス型のマルウェアが、インバウンド通信をリッスンする可能性がある |
| TROJAN : | トロイの木馬またはボット |
| SPREADER : | USB、他のドライブ、ネットワークなどに広がる |
|              |                                                       | 

##  <font color="yellow">proccesses</font>
* 指定されたファイルの実行中に作成されたプロセスのリスト。ただし、プロセスツリーを構築できる再帰的な方法で構造化された作成済みプロセスのみが列挙される。項目は以下の通です。

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| proccess_name :   | プロセス名                              | 
| proccess_id : | プロセスD | 
|              |                                                       | 

##  <font color="purple">dns_lookups</font>
*  特定のファイルによって実行されるドメイン名解決のリスト。当該リストは辞書型であり、各辞書には次のフィールドが含まれています。


|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| hostname :   | DNSクエリのホスト名                               | 
| resolved_ips : | 解決されたすべてのIPアドレス。NXドメインでは空の場合がある | 
|              |                                                       | 

##  <font color="cyan">files_copied</font>
* ある場所から別の場所にコピーされたファイルのリスト。当該リストはリスト型であり、リストのすべての項目に次のフィールドが含まれています。

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| destination : | 宛先ファイルのフルパス               | 
| source : | ソースファイルのフルパス                             | 
|              |                                                       | 

##  <font color="magenta">ip_trafic</font>
* 特定のファイルの実行中に見られる発信接続のリスト。当該リスタはリスト型であり、リストのすべての項目には次のフィールドが含まれています。

|              |                                                       | 
| ------------ | ----------------------------------------------------- | 
| transport_layer_protocol : | ICMP, IGMP, TCP, UDP, ESP, AH, L2TP, SCTP　のうちのいずれか.                       | 
| destination_ip : | IPアドレス                                       | 
| destination_port : | ポート番号                                    | 
|              |                                                       | 
