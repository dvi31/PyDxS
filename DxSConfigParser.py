#!/usr/bin/python2.7
import sys, traceback, argparse, time
import x509Certificate
import lxml.etree as ET


def convertNode(element, cert):
    x509Cert = x509Certificate.x509Certificate(cert.text)

    item = ET.SubElement(element, "X509CertificateList")
    item = ET.SubElement(item, "X509CertificateItem")

    ET.SubElement(item, "X509SubjectName").text = x509Cert.subject

    ET.SubElement(item, "X509SubjectName").text = x509Cert.subject
    ET.SubElement(item, "X509IssuerName").text = x509Cert.issuer
    ET.SubElement(item, "X509CreationDate").text = time.strftime("%Y-%m-%dT%H:%M:%S", x509Cert.creationDate.timetuple())
    ET.SubElement(item, "X509ExpirationDate").text = time.strftime("%Y-%m-%dT%H:%M:%S",
                                                                   x509Cert.expirationDate.timetuple())
    ET.SubElement(item, "X509Sha1").text = x509Cert.fingerprint
    ET.SubElement(item, "X509Certificate").text = cert.text

    element.remove(cert)


def configUpdater(doc, resourceList, superUserList, groupList):
    # Resource
    for element in resourceList.find('CryptoKeyList').iter('CryptoKey'):
        for cert in element.iter('X509Certificate'):
            # print cert.text
            convertNode(element, cert)

    # SuperUser
    for element in superUserList.iter('SuperUser'):
        for cert in element.iter('X509Certificate'):
            convertNode(element, cert)

    # Group
    for grp in groupList.iter('Group'):
        # Group Application
        for app in grp.iter('ApplicationList'):
            for element in app.iter('Application'):
                for cert in element.iter('X509Certificate'):
                    convertNode(element, cert)
        # Group User
        for user in grp.iter('UserList'):
            for element in user.iter('User'):
                for cert in element.iter('X509Certificate'):
                    convertNode(element, cert)


try:
    parser = argparse.ArgumentParser(description='DxS config parser.')
    parser.add_argument('configFile', metavar='--configFile', type=str, help='configFile')
    parser.add_argument('configType', metavar='--configType', type=str, help='configType')
    parser.add_argument('--outFile', metavar='-out', type=str, help='outFile')
    parser.add_argument('--xsl', metavar='--xsl', type=str, help='xsl')

    args = parser.parse_args()

    print "DxS config parser"
    print "====================================="
    print "configFile\t:", args.configFile
    print "configType\t:", args.configType
    print "xsl\t\t:", args.xsl
    print "outFile\t\t:", args.outFile

    dom = ET.parse(args.configFile)
    root = dom.getroot()
    configUpdater(dom,
                  root.find('SuperAdministration').find('ResourceList'),
                  root.find('SuperAdministration').find('SuperUserList'),
                  root.find('Administration').find('GroupList'))

    if args.outFile is not None:
        if args.xsl is not None:
            transform = ET.XSLT(ET.parse(args.xsl))
            with open(args.outFile, 'wb') as f:
                f.write(ET.tostring(transform(dom), pretty_print=True))
        else:
            dom.write(args.outFile, encoding='utf-8')

        dom.write(args.outFile + ".xml", encoding='utf-8')
        print "Config saved:  ", args.outFile
    else:
        if args.xsl is not None:
            transform = ET.XSLT(ET.parse(args.xsl))
            print ET.tostring(transform(dom), pretty_print=True)
        else:
            print root.toxml()

except Exception as e:
    print e
    traceback.print_exc(file=sys.stdout)
    sys.exit(3)
