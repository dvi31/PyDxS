#!/usr/bin/python2.7
import sys, traceback, argparse
import time, uuid
import csv
import DVSCaller, benchtool
import base64

try:
    exitCode = 0

    parser = argparse.ArgumentParser(description='DVS caller.')
    parser.add_argument('requestId', metavar='--requestId', type=str, help='RequestId')
    parser.add_argument('wsuri', metavar='--wsuri', type=str, help='WS URL')
    parser.add_argument('keystore', metavar='--keystore', type=str, help='Keystore (pem)')
    parser.add_argument('truststore', metavar='--truststore', type=str, help='Trustore (cer)')
    parser.add_argument('certificates', metavar='--certificates', type=str, help='CSV certificate file')
    parser.add_argument('--fileOut', metavar='-out', type=str, default="out/DVSVerifyCertificates.csv",
                        help='CSV result file')
    parser.add_argument('--refreshCRLs', metavar='-crl', type=bool, help='refreshCRLs',default=0)
    # parser.add_argument('--tag', metavar='-tag', type=str, help='tag')
    parser.add_argument('--verbose', metavar='-v', type=bool, help='Print SOAP Messages')
    parser.add_argument('--basepath', metavar='-v', type=str, default="echantillons/certificats/recette",
                        help='Base path certificates')

    args = parser.parse_args()
    print "DVS Caller "
    print "====================================="
    print "requestId\t: ", args.requestId
    print "wsuri\t\t: ", args.wsuri
    print "keystore\t: ", args.keystore
    print "truststore\t: ", args.truststore
    print "refreshCRLs\t: ", args.refreshCRLs
    print "certificates\t: ", args.certificates
    print "basepath\t: ", args.basepath
    print "fileOut\t\t: ", args.fileOut
    print "\n"

    dvsCaller = DVSCaller.DVSCaller(args.keystore, args.truststore, args.wsuri, args.verbose)
    parameters = dvsCaller.buildVerifyCertificateExParameter()
    parameters.requestId = args.requestId
    parameters.refreshCRLs = 1 if args.refreshCRLs else 0

    exitCode = 0
    wstime = 0

    with open(args.certificates, 'rb') as f:
        reader = csv.DictReader(f, delimiter=';')

        out = open(args.fileOut, 'wb')
        line = ['certId', 'policy', 'certPath', 'ExpectedResult', 'globalStatus', 'extendStatus', 'Time',
                'NonRegressionResult']
        out.write(';'.join(line) + '\n')

        for i, row in enumerate(reader):
            globalStatus = (0 if row['globalStatus'] is '' else int(row['globalStatus'], 0))
            extStatus = (0 if row['extendStatus'] is '' else int(row['extendStatus'], 0))
            parameters.transactionId = row['policy']
            parameters.tag = parameters.transactionId + "#" + row['certId']

            try:
                with open(args.basepath + "/" + row['certPath'], 'rb') as f:
                    parameters.certificate = base64.encodestring(f.read())

                if i == 0:  # for first check, do a blank call to open the socket
                    response = dvsCaller.verifyCertificateEx(parameters)

                response = dvsCaller.verifyCertificateEx(parameters)
                wstime += dvsCaller.getExecutionTime()
                extendStatus = None
                if response.opStatus == 0:
                    extendStatus = response.DVSDetailedStatus.DVSDetailedStatusStruct[0].DVSStatus
                    if row['ExpectedResult'] == 'Vrai' or row['ExpectedResult'] == 'True':
                        if response.DVSGlobalStatus == 0 and extendStatus == 0:
                            result = 'OK'
                        else:
                            result = 'KO'
                            exitCode = 2
                    else:
                        if response.DVSGlobalStatus != 0 or extendStatus != 0:
                            result = 'OK'
                        else:
                            result = 'KO'
                            exitCode = 2

                else:
                    result = 'ERROR opStatus:' + str(response.opStatus)
                    exitCode = 1

                roundTime = int(round(dvsCaller.getExecutionTime() / 1000, 0))
                line = row['certId'], row['policy'], row['certPath'], row['ExpectedResult'], \
                       str(response.DVSGlobalStatus), str(extendStatus), str(roundTime), result
                # print line
                out.write(';'.join(line) + '\n')


            except Exception as e:
                # print e
                line = row['certId'], row['policy'], row['certPath'], row['ExpectedResult'], "N/A", "N/A", "N/A", str(e)
                # print line
                out.write(';'.join(line) + '\n')

        out.close()

		
    print '\nExecution Time \t:', wstime, " ms"
	
    if exitCode == 0:
        print "\nStatus: OK"
    elif exitCode == 1:
        print "\nStatus: WARNING"
    else:
        print "\nStatus: ERROR"

    # print "\nList SSL sessions:"
    # print "\t", uuid.uuid4(), "=>", dvsCaller.getpeercert()

    sys.exit(exitCode)

except Exception as e:
    print e
    traceback.print_exc(file=sys.stdout)
    sys.exit(3)
