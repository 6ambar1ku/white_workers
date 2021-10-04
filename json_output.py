import pandas as pd
import csv

# df = pd.read_json('./MWScup_FFRI Datasets/ffridataset2021_malware.jsonl', orient='records', lines=True)

def data_read(path, mode, writer):
    """
    ファイルから1行ずつ読み込む
    """
    with open(path, mode) as f:
        row = f.readline() #1行目を読み込む
        i = 0
        while row:
            # print("---- Row data ----")
            # print("Type of ""data"":{}".format(type(row))) #str型
            # print(row)
            # print(row[0:10])
            sha256 = "".join(extract(row, "sha256"))
            ssdeep = "".join(extract(row, "ssdeep"))
            # print("sha256:", sha256)
            # print("ssdeep:", ssdeep)
            writer.writerow([sha256,ssdeep])
            # print("\n")
            row = f.readline() #次の行を読み込む
            i += 1
            # if i == 10:
            #   break
            print(i)
        

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
    # return str_origin[index_str: index_str+100]
            

if __name__ == "__main__":
    #読み込み対象ファイル
    path = 'C:/Users/nflabs-28/Downloads/MWScup_FFRI Datasets/MWScup_FFRI Datasets/ffridataset2021_malware.jsonl'
    #ファイルモード
    mode = "r" #読み込み用
    f = open("out.csv", "a", newline="")
    writer = csv.writer(f)
    data_read(path, mode, writer)
    f.close()