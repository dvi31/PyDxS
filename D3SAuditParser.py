#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
import sys, traceback, argparse, time
import x509Certificate
import lxml.etree as ET
from iso8601 import iso8601
import csv
from collections import OrderedDict


class BoxUA:
    _lockerName = None
    _boxName = None
    creationDate = None
    uaCode = None
    aName = None

    def __init__(self, _lockerName, _boxName, creationDate, uaCode, uaName):
        self._lockerName = _lockerName
        self._boxName = _boxName
        self.creationDate = creationDate
        self.uaCode = uaCode
        self.uaName = uaName

    def getId(self):
        return self._lockerName + "/" + self._boxName

    def getUACode(self):
        return self.uaCode


class UAReport:
    read = 0
    write = 0
    year = None
    month = None
    uaCode = None
    uaName = None

    def __init__(self, boxUA, year, month):
        self.uaCode = boxUA.uaCode
        self.uaName = boxUA.uaName
        self.year = year
        self.month = month

    def incrementRead(self):
        self.read += 1

    def incrementWrite(self):
        self.write += 1


def updateReport(year, month, ua, uaReports, isRead, byTrimestre):
    boxAuditReport = None
    key = None
    id = None
    if byTrimestre:
        id = getTrimestre(month)
        key = "%d/T%d %s" % (year, id, ua.getUACode())
    else:
        id = month
        key = "%d/%02d %s" % (year, id, ua.getUACode())

    if key in uaReports:
        boxAuditReport = uaReports.get(key)
    else:
        boxAuditReport = UAReport(ua, year, id)
        UAReport(ua, year, id)

    if isRead:
        boxAuditReport.incrementRead()
    else:
        boxAuditReport.incrementWrite()

    uaReports.update({key: boxAuditReport})


def getTrimestre(month):
    if month == 1 or month == 2 or month == 3:
        return 1
    if month == 4 or month == 5 or month == 6:
        return 2
    if month == 7 or month == 8 or month == 9:
        return 3
    if month == 10 or month == 11 or month == 12:
        return 4
    else:
        return None


def buildCSV(uaReports, isTrimestre):
    line = ['Date', 'UA', 'UA Name', 'Lecture', 'Ecriture', 'Nombre de Lecture / Ecriture']
    out = ';'.join(line) + '\n'
    if isTrimestre:
        dtFormat = "T%d %d;"
    else:
        dtFormat = "%02d/%d;"

    for uaReport in uaReports.items():
        out += dtFormat % (uaReport[1].month, uaReport[1].year)
        out += uaReport[1].uaCode + ";"
        out += uaReport[1].uaName + ";"
        out += str(uaReport[1].read) + ";"
        out += str(uaReport[1].write) + ";"
        out += str(uaReport[1].read + uaReport[1].write) + "\n"

    return out


try:
    parser = argparse.ArgumentParser(description='DxS config parser.')
    parser.add_argument('auditFile', metavar='--auditFile', type=str, help='auditFile')
    parser.add_argument('uaFile', metavar='--uaFile', type=str, help='uaFile')
    parser.add_argument('--boxToExclude', metavar='-bte', type=str, help='boxToExclude')
    parser.add_argument('--outFile', metavar='-out', type=str, help='outFile')

    args = parser.parse_args()

    print "DxS config parser"
    print "====================================="
    print "auditFile\t:", args.auditFile
    print "uaFile\t:", args.uaFile
    print "boxToExclude\t:", args.boxToExclude
    print "outFile\t\t:", args.outFile

    dom = ET.parse(args.auditFile)
    root = dom.getroot()

    uaConfig = OrderedDict()
    uaReports = OrderedDict()
    uaReportsDetail = OrderedDict()

    with open(args.uaFile, 'rb') as f:
        reader = csv.DictReader(f, delimiter=';')
        for i, row in enumerate(reader):
            boxUA = BoxUA(row['Locker'], row['Safebox'], row['Creation date'],
                          row['UA code'], row['UA name'])
            uaConfig.update({boxUA.getId(): boxUA})

    for ops in root.iter('Operations'):
        for op in ops.iter('Operation'):
            for params in op.iter('Parameters'):
                lockerbox = None
                safebox = None

                if "SECRET_CREATE" == op.attrib['Name']:
                    isRead = False
                elif "UNSEAL_SECRET" == op.attrib['Name'] or "SECRET_READ" == op.attrib[
                    'Name'] or "SECRET_READ_NEED_APPROBATION" == op.attrib['Name']:
                    isRead = True
                else:
                    continue

                for param in params.iter('Parameter'):
                    attr = param.attrib['Name']
                    if attr == "urn:dictao:d3s:reports:lockerbox-name":
                        lockerbox = param.find('Value').find('StringValue').text
                    elif attr == "urn:dictao:d3s:reports:safe-box-name":
                        safebox = param.find('Value').find('StringValue').text

                # skip test box
                if args.boxToExclude != None:
                    if args.boxToExclude in safebox: continue

                # all other locker had only safebox for the same UA
                if ("ARMOIRE_DOCUMENT" != lockerbox):
                    safebox = "*"

                date = iso8601.parse_date(op.find('Date').text)
                # date = time.strptime(op.find('Date').text, "%Y-%m-%dT%H:%M:%S.%f%Z")
                year = date.year
                month = date.month
                # print year, month

                key = lockerbox + "/" + safebox
                if key not in uaConfig:
                    ua = BoxUA("UNKNOW", lockerbox + "/" + safebox, "UNKNOW", lockerbox + "/" + safebox,
                               lockerbox + "/" + safebox)
                    uaConfig.update({key: ua})
                else:
                    ua = uaConfig.get(key)

                # by Trimestre
                updateReport(year, month, ua, uaReports, isRead, True);

                # by month
                updateReport(year, month, ua, uaReportsDetail, isRead, False);

    out = buildCSV(uaReports, True)
    out += "\n\n"
    out += buildCSV(uaReportsDetail, False)

    if args.outFile is not None:
        f = open(args.outFile, "w")
        f.write(out)
        f.close()
        print "\nReport saved \t:", args.outFile
    else:
        print out

except Exception as e:
    print e
    traceback.print_exc(file=sys.stdout)
    sys.exit(3)
