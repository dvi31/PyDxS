#!/usr/bin/python2.7

from pyasn1.codec.der.decoder import decode
from pyasn1_modules import rfc2459
import base64
import hashlib
from datetime import datetime


class x509Certificate:

    def __init__(self, certificate):
        cert = certificate.replace("-----BEGIN CERTIFICATE-----", '').replace("-----END CERTIFICATE-----", '')
        # print cert
        der = base64.b64decode(cert)
        cert, rest = decode(der, asn1Spec=rfc2459.Certificate())
        # print cert

        cert = cert['tbsCertificate']
        rdnsequence = cert['subject'][0]  # the subject is only composed by one component
        subject = ""
        for rdn in rdnsequence:
            oid, value = rdn[0]  # rdn only has 1 component: (object id, value) tuple
            subject = subject + ", " + str(value[2:])
        self.subject = subject[2:]

        rdnsequence = cert['issuer'][0]  # the subject is only composed by one component
        issuer = ""
        for rdn in rdnsequence:
            oid, value = rdn[0]  # rdn only has 1 component: (object id, value) tuple
            issuer = issuer + ", " + str(value[2:])
        self.issuer = issuer[2:]

        creationDate = cert['validity']['notBefore'][0]
        creationDate = datetime.strptime(str(creationDate), "%y%m%d%H%M%SZ")
        self.creationDate = creationDate

        expirationDate = cert['validity']['notAfter'][0]
        expirationDate = datetime.strptime(str(expirationDate), "%y%m%d%H%M%SZ")
        self.expirationDate = expirationDate

        self.fingerprint = self._fingerprint(der)

    def pprint(self):
        print "subject\t\t:", self.subject
        print "issuer\t\t:", self.issuer
        print "creationDate\t:", self.creationDate
        print "expirationDate\t:", self.expirationDate
        print "fingerprint\t:", self.fingerprint

    def _fingerprint(self, data, algorithm="sha1"):
        """ Method private to hash data
        data: data to hash
        algorithm : algorithm to use
        """
        try:
            fingerprint = hashlib.new(algorithm)
        except:
            raise Exception("Algorithm not supported _fingerprint method")
        fingerprint.update(data)
        return fingerprint.hexdigest()
