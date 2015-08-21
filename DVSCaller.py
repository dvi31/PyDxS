#!/usr/bin/python2.7
import sys, logging, time, threading
import benchtool
import DVSStatus
import DVSStatus
from suds.client import Client
from httpslib import HTTPSClientCertTransport


class DVSCaller:
    wsdl = "file:caller/wsdl/dxs/49/DVSInterfaceFrontEnd.wsdl"
    wsTime = -1

    def __init__(self, keyStore, trustStore, wsUri, verbose):
        self.transport = HTTPSClientCertTransport(keyStore, keyStore, trustStore)
        self.c = Client(self.wsdl, location=wsUri, transport=self.transport)
        if verbose:
            logging.basicConfig(level=logging.INFO)
            logging.getLogger('suds.client').setLevel(logging.INFO)
            logging.getLogger('suds.transport').setLevel(logging.DEBUG)

    def buildVerifyCertificateExParameter(self):
        return self.c.factory.create('verifyCertificateEx')

    def buildVerifySignatureExParameter(self):
        return self.c.factory.create('verifySignatureEx')

    def verifySignatureEx(self, parameters):
        ts = time.time()
        response = self.c.service.verifySignatureEx(parameters.requestId, parameters.transactionId,
                                                    parameters.refreshCRLs, parameters.tag,
                                                    parameters.signature, parameters.signedData,
                                                    parameters.signedDataHash)
        wsTime = time.time() - ts
        self.wsTime = int(wsTime * 1000)
        return response

    def verifyCertificateEx(self, parameters):
        ts = time.time()
        response = self.c.service.verifyCertificateEx(parameters.requestId, parameters.transactionId,
                                                      parameters.refreshCRLs, parameters.tag,
                                                      parameters.certificate)
        wsTime = time.time() - ts
        self.wsTime = int(wsTime * 1000)
        return response

    def getExecutionTime(self):
        return self.wsTime

    def getpeercert(self):
        # print "pprint ", pprint.pprint(transport.getpeercert())
        cert = self.transport.getpeercert()
        return ", ".join(str(val[0][1]) for val in cert['subject'])


class benchVerifyCertificate(benchtool.Bench):
    def __init__(self, threadID, counter, keystore, truststore, wsuri, requestId, transactionId, tag, certificate,
                 refreshCRLs):
        benchtool.Bench.__init__(self, threadID, counter)

        self.caller = DVSCaller(keystore, truststore, wsuri, False)
        self.parameters = self.caller.buildVerifyCertificateExParameter()
        self.parameters.requestId = requestId
        self.parameters.transactionId = transactionId
        self.parameters.tag = tag
        self.parameters.certificate = certificate
        self.parameters.refreshCRLs = 1 if refreshCRLs else 0

        # init SSL context with test transaction
        self.caller.verifyCertificateEx(self.parameters)

    def execute(self):
        response = self.caller.verifyCertificateEx(self.parameters)
        if response.opStatus == 0 and response.DVSGlobalStatus == 0:
            return True
        else:
            return False


class benchVerifySignature(benchtool.Bench):
    def __init__(self, threadID, counter, keystore, truststore, wsuri, requestId, transactionId, tag, signature,
                 signedData, signedDataHash, refreshCRLs):
        benchtool.Bench.__init__(self, threadID, counter)

        self.caller = DVSCaller(keystore, truststore, wsuri, False)
        self.parameters = self.caller.buildVerifySignatureExParameter()
        self.parameters.requestId = requestId
        self.parameters.transactionId = transactionId
        self.parameters.tag = tag
        self.parameters.signature.binaryValue = signature
        self.parameters.signedData.binaryValue = signedData
        self.parameters.signedDataHash = signedDataHash
        self.parameters.refreshCRLs = 1 if refreshCRLs else 0

        # init SSL context with test transaction
        self.caller.verifySignatureEx(self.parameters)

    def execute(self):
        response = self.caller.verifySignatureEx(self.parameters)
        if response.opStatus == 0 and response.DVSGlobalStatus == 0:
            return True
        else:
            return False


def ppResponse(response, wsTime):
    detailedStatus = None
    print '\nExecution Time \t:', wsTime, " ms\n"
    type=None

    if response.opStatus == 0:
        print 'requestId \t:', response.requestId
        print 'DVSArchiveId \t:', response.DVSArchiveId


    if hasattr(response, 'DVSDetailedStatus'):
        # print 'DVSDetailedStatus \t:', response.DVSDetailedStatus
        for status in response.DVSDetailedStatus.DVSDetailedStatusStruct:
            detailedStatus = status.DVSStatus
            type = status.Type
            # print status
            print "\n\tDonnee signee\n\t-------------"
            print "\tType de signature\t: ", type
            print "\tDN Signataire \t\t: ", status.SubjectName
            print "\tDVSStatus \t\t: ", detailedStatus
            print "\tCertificat \t\t: ", status.Certificate if hasattr(status, 'Certificate') else "Null"
            print "\tDonnees signees\t\t: ", status.SignedData if hasattr(status, 'SignedData') else "Null"
            print "\tStatut etendue \t\t: ", status.ExtendedStatus if hasattr(status, 'ExtendedStatus') else "Null"
            print ""

    print 'OpStatus \t:', response.opStatus
    print DVSStatus.pprint(DVSStatus.OpStatus(response.opStatus))

    if response.opStatus == 0:
        if type == 'CERT':
            dvs_global_status = DVSStatus.DVSGlobalStatusCert(response.DVSGlobalStatus)
            dvs_status = DVSStatus.DVSStatusCert(detailedStatus)
        else:
            dvs_global_status = DVSStatus.DVSGlobalStatusSign(response.DVSGlobalStatus)
            dvs_status = DVSStatus.DVSStatusSign(detailedStatus)

        print 'DVSGlobalStatus\t:', response.DVSGlobalStatus
        print DVSStatus.pprint(dvs_global_status)
        print "DVSStatus \t:", detailedStatus
        print DVSStatus.pprint(dvs_status)

    if response.opStatus == 0 and response.DVSGlobalStatus == 0 and detailedStatus == 0:
        exitCode = 0
    elif detailedStatus != 0:
        exitCode = 2
    else:
        exitCode = 1

    return exitCode
