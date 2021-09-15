import os
from os.path import join, dirname
from dotenv import load_dotenv

load_dotenv('.env')

AP = os.environ.get("VT_API_KEY") # 環境変数の値をAPに代入