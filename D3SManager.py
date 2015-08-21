#!/usr/bin/python2.7
import base64, uuid, hashlib, time, os
import logging
import D3SCaller
from suds.client import Client
from suds.sax.attribute import Attribute
from httpslib import HTTPSClientCertTransport
import urlparse, urllib
from suds.plugin import MessagePlugin


class D3SSecretManager():
    def __init__(self, authCaller, stoCaller):
        self.authCaller = authCaller
        self.stoCaller = stoCaller

    def write(self, applicantPath, motivation, boxPath, metadatas, data):
        global result, response
        time2 = 0
        result, time1, response = self.authCaller.grantWrite(applicantPath, motivation, boxPath)
        if result:
            result, time2, response = self.stoCaller.write(applicantPath, motivation, boxPath, response.securityToken,
                                                           response.certificates, metadatas, base64.encodestring(data))
        wstime = time1 + time2
        return result, wstime, response

    def read(self, applicantPath, motivation, depositPath):
        time2 = 0
        result, time1, response = self.authCaller.grantRead(applicantPath, motivation, depositPath)
        if result:
            result, time2, response = self.stoCaller.read(response.securityToken, response.depositProof)
        wstime = time1 + time2
        return result, wstime, response

    def delete(self, applicantPath, motivation, depositPath):
        time2 = 0
        result, time1, response = self.authCaller.grantDelete(applicantPath, motivation, depositPath)
        if result:
            result, time2, response = self.stoCaller.delete(applicantPath, motivation, depositPath,
                                                            response.securityToken)
        wstime = time1 + time2
        return result, wstime, response

    def buildPasswordMetadatas(self, login, domain):
        metadatas = self.stoCaller.buildMetadatasParameter()
        metadata = [self.stoCaller.buildStrMetadataParameter("appLogin", login),
                    self.stoCaller.buildStrMetadataParameter("appDomainName", domain)]
        metadatas.metadata = metadata
        return metadatas
