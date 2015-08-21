#!/usr/bin/python2.7
import base64, uuid, hashlib, time, os
import logging
import benchtool
from suds.client import Client
from suds.sax.attribute import Attribute
from httpslib import HTTPSClientCertTransport
import urlparse, urllib
import D3SManager
from suds.plugin import MessagePlugin


def path2url(path):
    return urlparse.urljoin(
        'file:', urllib.pathname2url(os.path.abspath(path)))


class D3SAuthorityCaller():
    wsdl = path2url("caller/wsdl/d3s/v2/v2_1_Authority.wsdl") + '#SecretPort'
    wsTime = -1

    def __init__(self, keyStore, trustStore, wsUri, verbose=False):
        self.transport = HTTPSClientCertTransport(keyStore, keyStore, trustStore)
        self.transport2 = HTTPSClientCertTransport(keyStore, keyStore, trustStore)
        self.secretPort = Client(self.wsdl, location=wsUri + "SecretPort", port='SecretPort', transport=self.transport)
        self.depositPort = Client(self.wsdl, location=wsUri + "DepositPort", port='DepositPort',
                                  transport=self.transport2)
        if verbose:
            logging.basicConfig(level=logging.INFO)
            logging.getLogger('suds.client').setLevel(logging.INFO)
            logging.getLogger('suds.transport').setLevel(logging.DEBUG)

    def buildAccessPermissions(self):
        return self.depositPort.factory.create('ns2:AccessPermissions')

    def setDeletable(self, applicantPath, motivation, resourcePath):
        response = None
        result = False
        ts = time.time()
        try:
            accessPermissions = self.buildAccessPermissions()
            accessPermissions.deletable = True
            response = self.depositPort.service.changeAccessPermissions(applicantPath,
                                                                        motivation, resourcePath, accessPermissions)
            result = True
        except Exception as e:
            response = e

        wsTime = time.time() - ts
        self.wsTime = int(wsTime * 1000)
        return result, self.wsTime, response

    def discard(self, applicantPath, motivation, resourcePath):
        response = None
        result = False
        ts = time.time()
        try:
            response = self.depositPort.service.discardDeposit(applicantPath, motivation, resourcePath)
            result = True
        except Exception as e:
            response = e

        wsTime = time.time() - ts
        self.wsTime = int(wsTime * 1000)
        return result, self.wsTime, response

    def grantWrite(self, applicantPath, motivation, resourcePath):
        response = None
        result = False
        ts = time.time()
        try:
            response = self.secretPort.service.grantWrite(applicantPath, motivation, resourcePath)
            if response is not None:
                result = True
        except Exception as e:
            response = e

        wsTime = time.time() - ts
        self.wsTime = int(wsTime * 1000)
        return result, self.wsTime, response

    def grantDelete(self, applicantPath, motivation, resourcePath):
        response = None
        result = False
        ts = time.time()
        try:
            response = self.secretPort.service.grantDelete(applicantPath, motivation, resourcePath)
            if response is not None:
                result = True
        except Exception as e:
            response = e

        wsTime = time.time() - ts
        self.wsTime = int(wsTime * 1000)
        return result, self.wsTime, response

    def grantRead(self, applicantPath, motivation, resourcePath):
        response = None
        result = False
        ts = time.time()
        try:
            response = self.secretPort.service.grantRead(applicantPath, motivation, resourcePath)
            if "DP_VALID_SIGNATURE" == response.status.code:
                result = True
        except Exception as e:
            response = e

        wsTime = time.time() - ts
        self.wsTime = int(wsTime * 1000)
        return result, self.wsTime, response

    def getpeercert(self):
        cert = self.transport.getpeercert()
        return ", ".join(str(val[0][1]) for val in cert['subject'])

    def getExcetionTime(self):
        return self.wsTime


class MyPlugin(MessagePlugin):
    def marshalled(self, context):
        context.envelope.attributes.append(Attribute('xmlns:nsdcom', 'http://www.dictao.com/d3s/xsd/v2010_10/Common'))

        child = context.envelope.getChild('Body').getChild('write')
        if child is not None:
            foo = child.getChild('securityToken')
            foo.setPrefix("nsdcom")
            foo = child.getChild('metadatas')
            foo.setPrefix("nsdcom")

        child = context.envelope.getChild('Body').getChild('read')
        if child is not None:
            foo = child.getChild('securityToken')
            foo.setPrefix("nsdcom")

        child = context.envelope.getChild('Body').getChild('delete')
        if child is not None:
            foo = child.getChild('securityToken')
            foo.setPrefix("nsdcom")


class D3SStorageCaller():
    wsdl = path2url("caller/wsdl/d3s/v2/v2_1_Storage.wsdl")
    wsTime = -1

    def __init__(self, keyStore, trustStore, wsUri, verbose=False):
        self.transport = HTTPSClientCertTransport(keyStore, keyStore, trustStore)
        self.secretPort = Client(self.wsdl, location=wsUri + "secret", transport=self.transport, plugins=[MyPlugin()])
        # self.secretPort.add_prefix('nsdcom', 'http://www.dictao.com/d3s/xsd/v2010_10/Common')
        if verbose:
            logging.basicConfig(level=logging.INFO)
            logging.getLogger('suds.client').setLevel(logging.INFO)
            logging.getLogger('suds.transport').setLevel(logging.DEBUG)

    def buildMetadatasParameter(self):
        return self.secretPort.factory.create('ns1:Metadatas')

    def buildSecurityTokenParameter(self):
        return self.secretPort.factory.create('ns1:securityToken')

    def buildStrMetadataParameter(self, name, value):
        metadata = self.secretPort.factory.create('ns1:Metadata')
        metadata.value.StringValue = value
        metadata._name = name
        metadata._type = "STRING_TYPE"
        return metadata

    def read(self, securityToken, depositProof):
        response = None
        result = False
        ts = time.time()
        try:
            response = self.secretPort.service.read(securityToken, depositProof)
            if "HASH_COMPARAISON_OK" == response.status.code:
                result = True
            response = base64.standard_b64decode(response.data)
        except Exception as e:
            response = e

        wsTime = time.time() - ts
        self.wsTime = int(wsTime * 1000)
        return result, self.wsTime, response

    def delete(self, applicantPath, motivation, depositPath, securityToken):
        response = None
        result = False
        ts = time.time()
        try:
            self.secretPort.service.delete(applicantPath, motivation, depositPath, securityToken)
            result = True
        except Exception as e:
            response = e

        wsTime = time.time() - ts
        self.wsTime = int(wsTime * 1000)
        return result, self.wsTime, response

    def write(self, applicantPath, motivation, containerPath, securityToken, certificates, metadatas, data):
        response = None
        result = False
        ts = time.time()
        try:
            response = self.secretPort.service.write(applicantPath, motivation, containerPath, securityToken,
                                                     certificates, metadatas, data)
            if response is not None:
                result = True
        except Exception as e:
            response = e

        wsTime = time.time() - ts
        self.wsTime = int(wsTime * 1000)
        return result, self.wsTime, response

    def getpeercert(self):
        cert = self.transport.getpeercert()
        return ", ".join(str(val[0][1]) for val in cert['subject'])

    def getExcetionTime(self):
        return self.wsTime


class bench(benchtool.Bench):
    def __init__(self, threadID, counter, keystore, truststore, authCaller, stoCaller, operation,
                 applicantPath, motivation, boxPath, login, domain, data):
        benchtool.Bench.__init__(self, threadID, counter)

        ulogin = login + str(threadID)

        self.authCaller = D3SAuthorityCaller(keystore, truststore, authCaller)
        self.stoCaller = D3SStorageCaller(keystore, truststore, stoCaller)
        self.secretMgr = D3SManager.D3SSecretManager(self.authCaller, self.stoCaller)
        self.metadatas = self.secretMgr.buildPasswordMetadatas(ulogin, domain)
        self.depositPath = "/DEPOSIT?_boxPath=" + boxPath + "&appLogin=" + \
                           urllib.quote_plus(ulogin) + "&appDomainName=" + urllib.quote_plus(domain)

        self.applicantPath = applicantPath
        self.motivation = motivation
        self.boxPath = boxPath
        self.data = data
        self.operation = operation

        # If read operation without write action, create test deposit
        if "R" == self.operation:
            self._execute("WR")
        else:
            self._execute(self.operation)

    def execute(self):
        return self._execute(self.operation)

    def _execute(self, operation):
        result = False

        # Write
        if "W" in operation:
            wr_result = self.secretMgr.write(self.applicantPath, self.motivation, self.boxPath, self.metadatas,
                                             self.data)
            result = wr_result[0]

        # Read
        if "R" in operation:
            read_result = self.secretMgr.read(self.applicantPath, self.motivation, self.depositPath)
            if result is not True: result = read_result[0]

        # Delete
        if "D" in operation:
            perm_result = self.authCaller.setDeletable(self.applicantPath, self.motivation, self.depositPath)
            discard_result = self.authCaller.discard(self.applicantPath, self.motivation, self.depositPath)
            del_result = self.secretMgr.delete(self.applicantPath, self.motivation, self.depositPath)
            if result is not True: result = del_result[0]

        return result

    def getpeercert(self):
        return self.authCaller.getpeercert(), self.stoCaller.getpeercert()


def ppResponse(wr_result, read_result, perm_result, discard_result, del_result, compareData, fileOut):
    wsTime = 0
    exitCode = 0

    if wr_result is not None:
        result, wstime, response = wr_result
        wsTime += wstime
        if result:
            print "\tWRITE \t\t: OK"
        else:
            print "\tWRITE \t\t: KO, ", response
            exitCode = 2

    if read_result is not None:
        result, wstime, response = read_result
        wsTime += wstime
        if compareData is not None and compareData != response:
            print "\tREAD \t\t: KO, read data mismatch"
            exitCode = 2
        elif result and compareData == response:
            print "\tREAD \t\t: OK"
            if fileOut is not None:
                f = open(fileOut, "w")
                f.write(response)
                f.close()
        else:
            print "\tREAD \t\t: KO, ", response
            exitCode = 2

    if perm_result is not None:
        result, wstime, response = perm_result
        wsTime += wstime
        if result:
            print "\tSETPERMISSION \t: OK"
        else:
            print "\tSETPERMISSION \t: KO, ", response
            exitCode = 2

    if discard_result is not None:
        result, wstime, response = discard_result
        wsTime += wstime
        if result:
            print "\tDISCARD \t: OK"
        else:
            print "\tDISCARD \t: KO, ", response
            exitCode = 2

    if del_result is not None:
        result, wstime, response = del_result
        wsTime += wstime
        if result:
            print "\tDELETE \t\t: OK"
        else:
            print "\tDELETE \t\t: KO, ", response
            exitCode = 1

    if exitCode == 0:
        print "\nD3S WRD: SUCCESS"
    elif exitCode == 2:
        print "\nD3S WRD: WARNING"
    else:
        print "\nD3S WRD: ERROR"

    print '\nExecution Time :', wsTime, " ms\n"

    return exitCode
