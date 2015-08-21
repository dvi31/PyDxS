#!/usr/bin/python2.7
import sys, traceback, argparse, socket
import base64, time, uuid
import DTSSCaller, benchtool

try:
    parser = argparse.ArgumentParser(description='DTSS caller.')
    parser.add_argument('transactionId', metavar='--transactionId', type=str, help='TransactionId')
    parser.add_argument('requestId', metavar='--requestId', type=str, help='RequestId')
    parser.add_argument('wsuri', metavar='--wsuri', type=str, help='WS URL')
    parser.add_argument('keystore', metavar='--keystore', type=str, help='Keystore (pem)')
    parser.add_argument('truststore', metavar='--truststore', type=str, help='Trustore (cer)')
    parser.add_argument('signature', metavar='--signature', type=str, help='Data to sign')
    parser.add_argument('--tag', metavar='-tag', type=str, help='tag')
    parser.add_argument('--signatureParameter', metavar='-sigparam', type=str, help='Signature Parameter')
    parser.add_argument('--signedFile', metavar='-out', type=str, help='Signed File out')
    parser.add_argument('--verbose', metavar='-v', type=bool, help='Print SOAP Messages')
    parser.add_argument('--bench', metavar='-bench', type=bool, help='Bench')
    parser.add_argument('--thread', metavar='-thread', type=int, help='Nb bench thread')
    parser.add_argument('--loop', metavar='-loop', type=int, help='Nb bench loop')

    args = parser.parse_args()
    tag = args.tag if args.tag is not None else socket.gethostname() + "#" + str(uuid.uuid4())

    print "DTSS Caller "
    print "====================================="
    print "transactionId\t: ", args.transactionId
    print "requestId\t: ", args.requestId
    print "tag\t\t: ", tag
    print "wsuri\t\t: ", args.wsuri
    print "keystore\t: ", args.keystore
    print "truststore\t: ", args.truststore
    print "signature\t: ", args.signature
    print "signedFile\t: ", args.signedFile

    with open(args.signature, 'rb') as f:
        b64data = base64.b64encode(f.read())

    if args.bench == None:
        caller = DTSSCaller.DTSSCaller(args.keystore, args.truststore, args.wsuri, args.verbose)

        parameters = caller.buildInsertTimeStampExParameter()
        parameters.requestId = args.requestId
        parameters.transactionId = args.transactionId
        parameters.tag = tag
        parameters.signature.binaryValue = b64data
        parameters.signatureParameter = args.signatureParameter
        parameters.pluginParameter = None

        response = caller.insertTimeStampEx(parameters)
        exitCode = DTSSCaller.ppResponse(response, caller.getExcetionTime(), args.signedFile)

        print "\nList SSL sessions:"
        print "\t", uuid.uuid4(), "=>", caller.getpeercert()
        sys.exit(exitCode)

    else:
        print "thread\t\t: ", args.thread
        print "loop\t\t: ", args.loop

        threads = []
        for x in range(0, args.thread):
            threads.append(
                DTSSCaller.benchInsertTimeStampEx(x, args.loop, args.keystore, args.truststore, args.wsuri,
                                                  args.requestId, args.transactionId, tag, b64data,
                                                  args.signatureParameter)
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
