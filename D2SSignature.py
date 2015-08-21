#!/usr/bin/python2.7
import sys, traceback, argparse, socket
import base64, time, uuid
import D2SCaller, benchtool

try:
    parser = argparse.ArgumentParser(description='D2S caller.')
    parser.add_argument('transactionId', metavar='--transactionId', type=str, help='TransactionId')
    parser.add_argument('requestId', metavar='--requestId', type=str, help='RequestId')
    parser.add_argument('wsuri', metavar='--wsuri', type=str, help='WS URL')
    parser.add_argument('keystore', metavar='--keystore', type=str, help='Keystore (pem)')
    parser.add_argument('truststore', metavar='--truststore', type=str, help='Trustore (cer)')
    parser.add_argument('signatureFormat', metavar='--signatureFormat', type=str, help='SignatureFormat')
    parser.add_argument('signatureType', metavar='--signatureType', type=str, help='SignatureType')
    parser.add_argument('dataToSign', metavar='--dataToSign', type=str, help='Data to sign')
    parser.add_argument('--signedFile', metavar='-out', type=str, help='Signed File out')
    parser.add_argument('--detachedSignature', metavar='-detached', type=str, help='Detached Signature File')
    parser.add_argument('--tag', metavar='-tag', type=str, help='tag')
    parser.add_argument('--isC14n', metavar='-c14n', type=bool, help='isC14n')
    parser.add_argument('--signatureParameter', metavar='-sigparam', type=str, help='Signature Parameter')
    parser.add_argument('--verbose', metavar='-v', type=bool, help='Print SOAP Messages')
    parser.add_argument('--bench', metavar='-bench', type=bool, help='Bench')
    parser.add_argument('--thread', metavar='-thread', type=int, help='Nb bench thread')
    parser.add_argument('--loop', metavar='-loop', type=int, help='Nb bench loop')

    args = parser.parse_args()
    tag = args.tag if args.tag is not None else socket.gethostname() + "#" + str(uuid.uuid4())
    
    print "D2S Caller "
    print "====================================="
    print "transactionId\t: ", args.transactionId
    print "requestId\t: ", args.requestId
    print "tag\t\t: ", tag
    print "wsuri\t\t: ", args.wsuri
    print "keystore\t: ", args.keystore
    print "truststore\t: ", args.truststore
    print "signatureFormat\t: ", args.signatureFormat
    print "signatureType\t: ", args.signatureType
    print "dataToSign\t: ", args.dataToSign
    print "detachedSign\t: ", args.detachedSignature
    print "signedFile\t: ", args.signedFile

    with open(args.dataToSign, 'rb') as f:
        b64data = base64.b64encode(f.read())

    if args.detachedSignature is not None:
        # used for detach signature
        signatureParameter = D2SCaller.buildSignatureParameter(args.signatureType,
                                                               args.detachedSignature,
                                                               args.isC14n)
    else:
        # TODO used for PDF signature
        signatureParameter = None  # args.signatureParameter

    print "signParameter\t: ", signatureParameter

    if args.bench == None:
        caller = D2SCaller.D2SCaller(args.keystore, args.truststore, args.wsuri, args.verbose)

        parameters = caller.buildSignatureExParameter()
        parameters.requestId = args.requestId
        parameters.transactionId = args.transactionId
        parameters.tag = tag
        parameters.dataToSign.binaryValue = b64data
        parameters.signatureFormat = args.signatureFormat
        parameters.signatureType = args.signatureType
        parameters.signatureParameter = signatureParameter
        parameters.detachedSignature = None
        parameters.signatureContext = None
        parameters.pluginParameter = None

        response = caller.signatureEx(parameters)

        exitCode = D2SCaller.ppResponse(response, caller.getExcetionTime(), args.signedFile)

        print "\nList SSL sessions:"
        print "\t", uuid.uuid4(), "=>", caller.getpeercert()
        sys.exit(exitCode)

    else:
        print "thread\t\t: ", args.thread
        print "loop\t\t: ", args.loop

        threads = []
        for x in range(0, args.thread):
            threads.append(
                D2SCaller.benchSignature(x, args.loop, args.keystore, args.truststore, args.wsuri,
                                         args.requestId, args.transactionId, tag, args.signatureFormat,
                                         args.signatureType, b64data, signatureParameter)
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

except Exception as e:
    print e
    traceback.print_exc(file=sys.stdout)
    sys.exit(3)
