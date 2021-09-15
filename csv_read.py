import csv
import ssdeep
import sys

csv_file = open("../malware.csv", "r", encoding="ms932", errors="", newline="" )
#リスト形式
f = csv.reader(csv_file, delimiter=",", doublequote=True, lineterminator="\r\n", quotechar='"', skipinitialspace=True)

fuzzyhash1 = "98304:QqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2g3x:QqPe1Cxcxk3ZAEUadzR8yc4gB"

header = next(f)

dic = {}
pc = 0
for row in f:
    if pc > 100:
        break
    pc += 1
    fuzzyhash2 = row[4]
    compare_value = ssdeep.compare(fuzzyhash1,fuzzyhash2)
    dic[row[3]] = compare_value

dic_sorted = sorted(dic.items(), key=lambda x:x[1], reverse = True)
for i in range(10):
    print(dic_sorted[i])
    print("------")

# 閲覧用
# i = 1
# for row in f:
#     i+=1
#     # if i==10:
#     #     break
#     fuzzyhash2 = row
#     #print(fuzzyhash2)
# print(i)

