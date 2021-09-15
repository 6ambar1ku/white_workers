import csv
#import pyimpfuzzy
import ssdeep
import sys
#import pefile

csv_file = open("./malware.csv", "r", encoding="ms932", errors="", newline="" )
#リスト形式
f = csv.reader(csv_file, delimiter=",", doublequote=True, lineterminator="\r\n", quotechar='"', skipinitialspace=True)
#辞書形式
# f = csv.DictReader(csv_file, delimiter=",", doublequote=True, lineterminator="\r\n", quotechar='"', skipinitialspace=True)

#header = next(f)
#print(header)
#i = 1
# for row in f:
#     i+=1
#     if i==10:
#         break
#     #rowはList
#     #row[0]で必要な項目を取得することができる
#     print(row)


fuzzyhash1 = "98304:QqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2g3x:QqPe1Cxcxk3ZAEUadzR8yc4gB"
fuzzyhash2 = "98304:QqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2g3x:QqPe1Cxcxk3ZAEUadzR8yc4gB"
print("ssdeep1: %s" % fuzzyhash1)
print("ssdeep2: %s" % fuzzyhash2)
print(">>> ssdeep.compare score: %i/100¥n" % ssdeep.compare(fuzzyhash1,fuzzyhash2))