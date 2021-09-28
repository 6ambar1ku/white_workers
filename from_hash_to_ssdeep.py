from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
import json
import settings
from rich import print
from rich.console import _COLOR_SYSTEMS_NAMES, Console
from rich.markdown import Markdown
from rich.tree import Tree
import argparse

api_key = settings.AP
vt_api_files = VirusTotalAPIFiles(api_key)

# optionで-qを指定すれば、README.mdからコンソールに出力しない
parser = argparse.ArgumentParser()
parser.add_argument("-q", "--quit_showing_asciiart", help="If you don't wanna show ascii art. Please add '-q' to the command", action="store_true")

# optionで-f <path> を指定すれば、txt形式でツリー構造のデータを保存
parser.add_argument("-f", "--file_output_txt", help="If you wanna see this data by txt. Please add '-f' <path> to the command")
args = parser.parse_args()

# 出力用ツリーの作成
tree = Tree("attributes")

# ハッシュ値を元にssdeepの値をVirus TotalAPIから引き出す関数
def result_ssdeep(hash1):
    try:
        result_ssdeep = vt_api_files.get_report(hash1)
    except VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
            result_ssdeep = json.loads(result_ssdeep)
            ssdeep = result_ssdeep["data"]["attributes"]["ssdeep"]
            print(ssdeep)
            
        else:
            print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')

# ハッシュ値を元にマルウェアの振る舞いをVirus TotalAPIから引き出す関数
def  result_behavior(hash2, flag):
    try:
        result_behavior = vt_api_files.get_relationship(hash2, "/behaviours", 20)
    except VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
            result_behavior = json.loads(result_behavior)

             
            # テスト用(jsonファイル出力)
            # result = result_behavior
            # result = json.dumps(result, sort_keys=False, indent=4)
            # with open("./test.json", 'a') as outfile:
                # print(result, file=outfile)

            count_of_attributes = len(result_behavior["data"])
            # すべての値を列挙する
            for i in range(count_of_attributes):
                d = result_behavior["data"][i]["attributes"]
                sandbox_name = d["sandbox_name"]
                lower_tree = tree.add(str(i)+"_sandbox_name："+sandbox_name)
                command_tree = lower_tree.add("[red]command_executions")
                tags_tree = lower_tree.add("[blue]tags")
                verdicts_tree = lower_tree.add("[green]verdicts")

                if(("command_executions" in d) == True and ("tags" in d) == True and ("verdicts" in d) == True):
                    for command_executions in result_behavior["data"][i]["attributes"]["command_executions"]:
                        command_tree.add(command_executions)
                    for tags in result_behavior["data"][i]["attributes"]["tags"]:
                        tags_tree.add(tags)
                    for verdicts in result_behavior["data"][i]["attributes"]["verdicts"]:
                        verdicts_tree.add(verdicts)

                elif(("command_executions" in d) == False and ("tags" in d) == True and ("verdicts" in d) == True):
                    command_tree.add("NULL")
                    for tags in result_behavior["data"][i]["attributes"]["tags"]:
                        tags_tree.add(tags)
                    for verdicts in result_behavior["data"][i]["attributes"]["verdicts"]:
                        verdicts_tree.add(verdicts)
                
                elif(("command_executions" in d) == False and ("tags" in d) == False and ("verdicts" in d) == True):
                    command_tree.add("NULL")
                    tags_tree.add("NULL")
                    for verdicts in result_behavior["data"][i]["attributes"]["verdicts"]:
                        verdicts_tree.add(verdicts)
                        tags_tree.add(tags)
                    verdicts_tree.add("NULL")

                elif(("command_executions" in d) == True and ("tags" in d) == False and ("verdicts" in d) == True):
                    for command_executions in result_behavior["data"][i]["attributes"]["command_executions"]:
                        command_tree.add(command_executions)
                    tags_tree.add("NULL")
                    for verdicts in result_behavior["data"][i]["attributes"]["verdicts"]:
                        verdicts_tree.add(verdicts)

                elif(("command_executions" in d) == False and ("tags" in d) == True and ("verdicts" in d) == False):
                    command_tree.add("NULL")
                    for tags in result_behavior["data"][i]["attributes"]["tags"]:
                        tags_tree.add(tags)
                    verdicts_tree.add("NULL")

                elif(("command_executions" in d) == False and ("tags" in d) == True and ("verdicts" in d) == True):
                    command_tree.add("NULL")
                    for tags in result_behavior["data"][i]["attributes"]["tags"]:
                        tags_tree.add(tags)
                    for verdicts in result_behavior["data"][i]["attributes"]["verdicts"]:
                        verdicts_tree.add(verdicts)

                else:
                    command_tree.add("NULL")
                    tags_tree.add("NULL")
                    verdicts_tree.add("NULL")

                #flag=2ならprocessesをツリーに追加
                if flag == 2:
                    processes_tree = lower_tree.add("[yellow]processes")
                    if("processes_tree" in d) == True:
                        processes_id = processes_tree.add("[yellow]process_id")
                        processes_id.add("[yellow]process_name")
                        list_processes = result_behavior["data"][i]["attributes"]["processes_tree"]
                        count_of_processes = len(result_behavior["data"][i]["attributes"]["processes_tree"])
                        for j in range(count_of_processes):
                            processes = processes_tree.add(list_processes[j]["process_id"])
                            processes.add(list_processes[j]["name"])                                       
                    else:
                        processes_tree.add("NULL")

                #flag=3ならdns_lookupsをツリーに追加
                elif flag == 3:
                    dns_tree = lower_tree.add("[purple]dns_lookups")
                    if("dns_lookups" in d) == True:
                        hostname = dns_tree.add("[purple]hostname")
                        list_dns = result_behavior["data"][i]["attributes"]["dns_lookups"]
                        count_of_dns = len(result_behavior["data"][i]["attributes"]["dns_lookups"])
                        for j in range(count_of_dns):
                            count_of_dns_resolved = len(result_behavior["data"][i]["attributes"]["dns_lookups"][j]["resolved_ips"])
                            resolved_ips = hostname.add(list_dns[j]["hostname"])
                            resolved_ips.add("[purple]resolved_ips")
                            for k in range(count_of_dns_resolved):
                                resolved_ips.add(list_dns[j]["resolved_ips"][k])                             
                    else:
                        dns_tree.add("NULL")

                #flag=4ならfiles_copiedをツリーに追加
                elif flag == 4:
                    files_tree = lower_tree.add("[cyan]files_copied")
                    if("files_copied" in d) == True:
                        files_source = files_tree.add("[cyan]source")
                        files_source.add("[cyan]destination")
                        list_files = result_behavior["data"][i]["attributes"]["files_copied"]
                        count_of_files = len(result_behavior["data"][i]["attributes"]["files_copied"])
                        for j in range(count_of_files):
                            files = files_tree.add(list_files[j]["source"])
                            files.add(list_files[j]["destination"])                              
                    else:
                        files_tree.add("NULL")

                #flag=5ならip_trafficをツリーに追加
                elif flag == 5:
                    ip_tree = lower_tree.add("[magenta]ip_traffic")
                    if("ip_traffic" in d) == True:
                        ip_transport = ip_tree.add("[magenta]transport_layer_protocol")
                        ip_transport.add("[magenta]destination_ip")
                        ip_transport.add("[magenta]destination_port")       
                        list_ip = result_behavior["data"][i]["attributes"]["ip_traffic"]
                        count_of_ip = len(result_behavior["data"][i]["attributes"]["ip_traffic"])
                        for j in range(count_of_ip):
                            if("transport_layer_protocol" in list_ip[j]) == True:
                                ip_trans = ip_tree.add(list_ip[j]["transport_layer_protocol"])
                                ip_trans.add(list_ip[j]["destination_ip"])
                                ip_trans.add(str(list_ip[j]["destination_port"]))
                            else:
                                ip_trans = ip_tree.add("NULL")
                                ip_trans.add(list_ip[j]["destination_ip"])
                                ip_trans.add(str(list_ip[j]["destination_port"])) 
                    else:
                        ip_tree.add("NULL")

                #flag=6ならprocesses, dns_lookups, files_copied, ip_trafficをツリーに追加
                elif flag == 6:
                    processes_tree = lower_tree.add("[yellow]processes")
                    if("processes_tree" in d) == True:
                        processes_id = processes_tree.add("[yellow]process_id")
                        processes_id.add("[yellow]process_name")
                        list_processes = result_behavior["data"][i]["attributes"]["processes_tree"]
                        count_of_processes = len(result_behavior["data"][i]["attributes"]["processes_tree"])
                        for j in range(count_of_processes):
                            processes = processes_tree.add(list_processes[j]["process_id"])
                            processes.add(list_processes[j]["name"])                    
                    else:
                        processes_tree.add("NULL")

                    dns_tree = lower_tree.add("[purple]dns_lookups")
                    if("dns_lookups" in d) == True:
                        hostname = dns_tree.add("[purple]hostname")
                        list_dns = result_behavior["data"][i]["attributes"]["dns_lookups"]
                        count_of_dns = len(result_behavior["data"][i]["attributes"]["dns_lookups"])
                        for j in range(count_of_dns):
                            count_of_dns_resolved = len(result_behavior["data"][i]["attributes"]["dns_lookups"][j]["resolved_ips"])
                            resolved_ips = hostname.add(list_dns[j]["hostname"])
                            resolved_ips.add("[purple]resolved_ips")
                            for k in range(count_of_dns_resolved):
                                resolved_ips.add(list_dns[j]["resolved_ips"][k])
                    else:
                        dns_tree.add("NULL")

                    files_tree = lower_tree.add("[cyan]files_copied")
                    if("files_copied" in d) == True:
                        files_source = files_tree.add("[cyan]source")
                        files_source.add("[cyan]destination")
                        list_files = result_behavior["data"][i]["attributes"]["files_copied"]
                        count_of_files = len(result_behavior["data"][i]["attributes"]["files_copied"])
                        for j in range(count_of_files):
                            files = files_tree.add(list_files[j]["source"])
                            files.add(list_files[j]["destination"])
                    else:
                        files_tree.add("NULL")

                    ip_tree = lower_tree.add("[magenta]ip_traffic")
                    if("ip_traffic" in d) == True:
                        ip_transport = ip_tree.add("[magenta]transport_layer_protocol")
                        ip_transport.add("[magenta]destination_ip")
                        ip_transport.add("[magenta]destination_port")       
                        list_ip = result_behavior["data"][i]["attributes"]["ip_traffic"]
                        count_of_ip = len(result_behavior["data"][i]["attributes"]["ip_traffic"])
                        for j in range(count_of_ip):
                            if("transport_layer_protocol" in list_ip[j]) == True:
                                ip_trans = ip_tree.add(list_ip[j]["transport_layer_protocol"])
                                ip_trans.add(list_ip[j]["destination_ip"])
                                ip_trans.add(str(list_ip[j]["destination_port"]))
                            else:
                                ip_trans = ip_tree.add("NULL")
                                ip_trans.add(list_ip[j]["destination_ip"])
                                ip_trans.add(str(list_ip[j]["destination_port"])) 
                    else:
                        ip_tree.add("NULL")

        else:
            print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')

# txtとしてデータを保存するための関数
def file_output_txt(path, data):
    file_txt = path + "white_workers.txt"
    with open(file_txt, 'w', encoding='utf-8') as f:
        print(data, file=f)

# mdファイルからの出力
if args.quit_showing_asciiart == False:
    console = Console()
    with open("C:/Users/nflabs-11/Desktop/white_workers/white_workers/README.md", encoding="utf-8") as f:
        markdown = Markdown(f.read())
    console.print(markdown)

# optionで出力するツリー構造データを変更(3回間違えるとプログラムを終了)
for i in range(3):
    num_option = input("which options do you want to use??(1:default, 2:+=processes, 3:+=dns_lookups, 4:+=files_copied, 5:+=ip_traffic, 6:all)：")
    if num_option == "1":
        flag = 1
        print("You selected option 1")
        break
    elif num_option == "2":
        flag = 2
        print("You selected option 2")
        break
    elif num_option == "3":
        print("You selected option 3")
        flag = 3
        break
    elif num_option == "4":
        print("You selected option 4")
        flag = 4
        break
    elif num_option == "5":
        print("You selected option 5")
        flag = 5
        break
    elif num_option == "6":
        print("You selected option 6")
        flag = 6
        break
    else:
        print("[red]this is incorrect number.")
        if i == 2:
            print("[red]You typo three times. Sorry shutdown this program.[/red]")
            exit()
        continue

# 入力したいハッシュ値に応じて入力値の正誤を判定(3回間違えるとプログラムを終了)
for i in range(3):
    num_hash = input("which hash algorithm do you want to use??(1:md5, 2:sha-1, 3:sha-256)：")

    if num_hash == "1":
        md5 = input("You selected md5. Please enter your hash value:")
        if len(md5)!=32:
            print("[red]The number of characters is not appropriate[/red]")
            exit()
        result_ssdeep(md5)
        break
    
    elif num_hash == "2":
        sha_1 = input("You selected sha-1. Please enter your hash value:")
        if len(sha_1)!=40:
            print("[red]The number of characters is not appropriate[/red]")
            exit()
        result_ssdeep(sha_1)
        break
    
    elif num_hash == "3":
        sha_256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa" # input("You selected sha-256. Please enter your hash value:")
        if len(sha_256)!=64:
            print("[red]The number of characters is not appropriate[/red]")
            exit()
        # result_ssdeep(sha_256)
        result_behavior(sha_256, flag)
        if flag == 1:
            print("default")
        elif flag == 2:
            print("default+processes")
        elif flag == 3:
            print("default+dns_lookups")
        elif flag == 4:
            print("default+files_copied")
        elif flag == 5:
            print("default+ip_traffic")
        elif flag == 6:
            print("all")
        
        # 作成した木構造データの出力
        print("\n")
        print(tree)
        # txt出力するときはfile_output_txt関数を呼び出し
        if args.file_output_txt != None:
            file_output_txt(args.file_output_txt, tree)
        break
    
    else:
        print("[red]this is incorrect number.")
        if i == 2:
            print("[red]You typo three times. Sorry shutdown this program.[/red]")
            exit()
        continue
