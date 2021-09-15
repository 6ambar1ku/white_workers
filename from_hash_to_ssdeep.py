from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
import json
import settings

api_key = settings.AP
vt_api_files = VirusTotalAPIFiles(api_key) #APIキー

def result_ssdeep(hash1):
    try:
        result_ssdeep = vt_api_files.get_report(hash1) #hash
    except VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
            result_ssdeep = json.loads(result_ssdeep)
            ssdeep = result_ssdeep["data"]["attributes"]["ssdeep"]
            print(ssdeep)
            
        else:
            print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')


def  result_behavior(hash2):
    try:
        result_behavior = vt_api_files.get_relationship(hash2) #hash
    except VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
            result_behavior = json.loads(result_behavior)
            result = result_behavior["data"][1]["attributes"]["command_executions"][0]
            print(result)
            
        else:
            print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')


num = input("which hash algorithm do you want to use??(1:md5, 2:sha-1, 3:sha-256)：")
if num == "1":
    md5 = input("You selected md5. Please enter your hash value:")
    if len(md5)!=32:
        print("The number of characters is not appropriate")
        exit()
    result_ssdeep(md5)

elif num == "2":
    sha_1 = input("You selected sha-1. Please enter your hash value:")
    if len(sha_1)!=40:
        print("The number of characters is not appropriate")
        exit()
    result_ssdeep(sha_1)
    
elif num == "3":
    sha_256 = input("You selected sha-256. Please enter your hash value:")
    if len(sha_256)!=64:
        print("The number of characters is not appropriate")
        exit()
    result_ssdeep(sha_256)
    result_behavior(sha_256)
    
else:
    print("this is incorrect number. Sorry shutdown this program.")
    exit()
