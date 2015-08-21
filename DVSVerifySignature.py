#!/usr/bin/python2.7
import sys, traceback, argparse, socket
import time, uuid
import base64
import DVSCaller, benchtool


try:
    exitCode = 0

    parser = argparse.ArgumentParser(description='DVS caller.')
    parser.add_argument('transactionId', metavar='--transactionId', type=str, help='TransactionId')
    parser.add_argument('requestId', metavar='--requestId', type=str, help='RequestId')
    parser.add_argument('wsuri', metavar='--wsuri', type=str, help='WS URL')
    parser.add_argument('keystore', metavar='--keystore', type=str, help='Keystore (pem)')
    parser.add_argument('truststore', metavar='--truststore', type=str, help='Trustore (cer)')
    parser.add_argument('signature', metavar='--signature', type=str, help='Signature a valider')
    parser.add_argument('--signedData', metavar='-data', type=str, help='Donnee objet de la signature')
    parser.add_argument('--signedDataHash', metavar='--ash', type=str, help='Empreinte de la donnee signee')
    parser.add_argument('--refreshCRLs', metavar='-crl', type=bool, help='refreshCRLs')
    parser.add_argument('--tag', metavar='-tag', type=str, help='tag')
    parser.add_argument('--verbose', metavar='-v', type=bool, help='Print SOAP Messages')
    parser.add_argument('--bench', metavar='-bench', type=bool, help='Bench')
    parser.add_argument('--thread', metavar='-thread', type=int, help='Nb bench thread')
    parser.add_argument('--loop', metavar='-loop', type=int, help='Nb bench loop')

    args = parser.parse_args()
    tag = args.tag if args.tag is not None else socket.gethostname() + "#" + str(uuid.uuid4())
    
    print "DVS Caller "
    print "====================================="
    print "transactionId\t: ", args.transactionId
    print "requestId\t: ", args.requestId
    print "tag\t\t: ", tag
    print "wsuri\t\t: ", args.wsuri
    print "keystore\t: ", args.keystore
    print "truststore\t: ", args.truststore
    print "refreshCRLs\t: ", args.refreshCRLs
    print "signature\t: ", args.signature
    print "signedData\t: ", args.signedData
    print "signedDataHash\t: ", args.signedDataHash

    with open(args.signature, 'rb') as f:
        signature = base64.b64encode(f.read())

    if args.signedData is not None:
        with open(args.signedData, 'rb') as f:
            signedData = base64.b64encode(f.read())
    else:
        signedData = None

    if args.bench == None:
        dvsCaller = DVSCaller.DVSCaller(args.keystore, args.truststore, args.wsuri, args.verbose)

        parameters = dvsCaller.buildVerifySignatureExParameter()
        parameters.requestId = args.requestId
        parameters.transactionId = args.transactionId
        parameters.tag = tag
        parameters.signature.binaryValue = signature
        parameters.signedData.binaryValue = signedData
        parameters.signedDataHash = args.signedDataHash
        parameters.refreshCRLs = 1 if args.refreshCRLs else 0

        response = dvsCaller.verifySignatureEx(parameters)

        exitCode = DVSCaller.ppResponse(response, dvsCaller.getExecutionTime())

        print "\nList SSL sessions:"
        print "\t", uuid.uuid4(), "=>", dvsCaller.getpeercert()
    else:
        print "thread\t\t: ", args.thread
        print "loop\t\t: ", args.loop

        threads = []
        for x in range(0, args.thread):
            threads.append(
                DVSCaller.benchVerifySignature(x, args.loop, args.keystore, args.truststore, args.wsuri,
                                               args.requestId, args.transactionId, tag, signature,
                                               signedData, args.signedDataHash, args.refreshCRLs)
            )

        start = time.time()
        for thread in threads:
            thread.start()

        for thread in threads:
            while thread.isRunning() is True:
                time.sleep(0.1)
        end = time.time()
        tms = round((end - start) * 1000, 3)

        print benchtool.pprintBenchHeader()
        for thread in threads:
            print thread.pprintBenchResult()
        print benchtool.pprintBenchTotal(threads, tms)

        print "\nList SSL sessions:"
        for thread in threads:
            print "\t", thread.threadID, "=>", thread.getpeercert()

    sys.exit(exitCode)

except Exception as e:
    print e
    traceback.print_exc(file=sys.stdout)
    sys.exit(3)
