import csv
import ssdeep
import sys

def comp(ssdeep1):

    csv_file = open("../out.csv", "r", encoding="ms932", errors="", newline="" )
    # リスト形式で読み込む
    f = csv.reader(csv_file, delimiter=",", doublequote=True, lineterminator="\r\n", quotechar='"', skipinitialspace=True)
    header = next(f)

    dic = {}
    pc = 0
    for row in f:
        if pc > 100:
            break
        pc += 1
        ssdeep2 = row[1]
        compare_value = ssdeep.compare(ssdeep1,ssdeep2)
        dic[row[0]] = compare_value

    dic_sorted = sorted(dic.items(), key=lambda x:x[1], reverse = True)
    
    return_dic = {}
    # 上位10件を出力する
    for i in range(10):
        print(dic_sorted[i])
        print("------")
        return_dic[dic_sorted[i][0]] = dic_sorted[i][1] 

    return return_dic