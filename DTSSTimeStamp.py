#!/usr/bin/python2.7
import sys, traceback, argparse, socket
import base64, time, uuid, hashlib
import TSACaller, benchtool
import httpslib

try:
    parser = argparse.ArgumentParser(description='DTSS caller.')
    parser.add_argument('transactionId', metavar='--transactionId', type=str, help='TransactionId')
    parser.add_argument('wsuri', metavar='--wsuri', type=str, help='WS URL')
    parser.add_argument('dataToTS', metavar='--dataToTimeStamp', type=str, help='Data to timestamp')
    parser.add_argument('vaFile', metavar='--vaFile', type=str, help='Timestamp cert')
    parser.add_argument('--keystore', metavar='--keystore', type=str, help='Keystore (pem)')
    parser.add_argument('--truststore', metavar='--truststore', type=str, help='Trustore (cer)')
    parser.add_argument('--outFile', metavar='-out', type=str, help='Signed File out')
    parser.add_argument('--hash', metavar='-h', type=str, default="sha256",
                        help='default sha256 [sha256|sha512|sha1|md5]')
    parser.add_argument('--tag', metavar='-tag', type=str, help='tag')
    parser.add_argument('--verbose', metavar='-v', type=bool, help='Print SOAP Messages')
    parser.add_argument('--bench', metavar='-bench', type=bool, help='Bench')
    parser.add_argument('--thread', metavar='-thread', type=int, help='Nb bench thread')
    parser.add_argument('--loop', metavar='-loop', type=int, help='Nb bench loop')

    args = parser.parse_args()
    tag = args.tag if args.tag is not None else socket.gethostname() + "#" + str(uuid.uuid4())

    print "DTSS Caller "
    print "====================================="
    print "transactionId\t:", args.transactionId
    print "tag\t\t:", tag
    print "hash\t\t:", args.hash
    print "wsuri\t\t:", args.wsuri
    print "keystore\t:", args.keystore
    print "truststore\t:", args.truststore
    print "dataToTS\t:", args.dataToTS + "\n"

    url = args.wsuri + "?transactionID=" + args.transactionId + "&tag=" + tag

    # with open(args.vaFile, 'rb') as f:
    #     certificate = f.read()

    hashValue = TSACaller.getHash(args.dataToTS, args.hash)
    include_tsa_certificate = False

    if args.bench == None:
        # if args.keystore is not None :
        #     handler = HTTPSClientAuthHandler(args.keystore, args.keystore, args.truststore)

        caller = TSACaller.TSACaller(url, args.vaFile, args.hash, args.keystore, args.truststore)
        response, res = caller.timeStamp(hashValue, include_tsa_certificate)
        if response is False:
            print "\nstatus\t\t: KO,", res
            exitCode = TSACaller.ppResponse(None, caller.getExcetionTime(), args.outFile)
        else:
            print "\nstatus\t\t: OK,", res
            exitCode = TSACaller.ppResponse(response, caller.getExcetionTime(), args.outFile)

        if caller.getpeercert() is not None:
            print "\nList SSL sessions:"
            print "\t", uuid.uuid4(), "=>", caller.getpeercert()
        sys.exit(exitCode)

    else:
        print "thread\t\t: ", args.thread
        print "loop\t\t: ", args.loop
        threads = []
        for x in range(0, args.thread):
            threads.append(
                TSACaller.benchTimeStamp(x, args.loop, url, args.vaFile, args.hash, hashValue, include_tsa_certificate,
                                         args.keystore, args.truststore)
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
