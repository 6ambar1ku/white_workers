import csv
#import pyimpfuzzy
import ssdeep
import sys
#import pefile

csv_file = open("../malware.csv", "r", encoding="ms932", errors="", newline="" )
#リスト形式
f = csv.reader(csv_file, delimiter=",", doublequote=True, lineterminator="\r\n", quotechar='"', skipinitialspace=True)
#辞書形式
# f = csv.DictReader(csv_file, delimiter=",", doublequote=True, lineterminator="\r\n", quotechar='"', skipinitialspace=True)

fuzzyhash1 = "98304:QqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2g3x:QqPe1Cxcxk3ZAEUadzR8yc4gB"

header = next(f)
# print(header)

i = 1
for row in f:
    fuzzyhash2 = row[4]

    compare_value = ssdeep.compare(fuzzyhash1,fuzzyhash2)
    if compare_value > 98:
        print(fuzzyhash2)
        print(">>> ssdeep.compare score: %i/100¥n" % compare_value)

# 閲覧用
# i = 1
# for row in f:
#     i+=1
#     # if i==10:
#     #     break
#     fuzzyhash2 = row
#     #print(fuzzyhash2)
# print(i)

