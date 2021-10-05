import pandas as pd
import ssdeep
from tqdm import tqdm

def comp(ssdeep1):
    # ファイルから1行ずつ読み込む
    dic = {}

    with open("Desktop/white_workers/MWScup_FFRI Datasets/ffridataset2021_malware.jsonl", "r") as f:
        row = f.readline() #1行目を読み込む
        i = 0
        pbar = tqdm(total=75000)
        while row:
            sha256 = "".join(extract(row, "sha256"))
            ssdeep2 = "".join(extract(row, "ssdeep"))

            compare_value = ssdeep.compare(ssdeep1,ssdeep2)
            dic[sha256] = compare_value

            row = f.readline() #次の行を読み込む
            i += 1
            pbar.update(1)
        pbar.close()
        
    dic_sorted = sorted(dic.items(), key=lambda x:x[1], reverse = True)
    
    return dic_sorted
        

def extract(str_origin, str_find):
    index_str = str_origin.find(str_find)
    i = index_str
    count = 0  

    while 1:
        if str_origin[i] == '"':
            count += 1
        i += 1
        if count == 2:
            break
    
    str_return = []
    
    while 1:
        str_return.append(str_origin[i])
        i += 1
        if str_origin[i] == '"':
            break
    
    return str_return