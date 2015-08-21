#!/usr/bin/python2.7
import sys, traceback, argparse, socket
import base64, time, uuid
import urllib
import D3SCaller, D3SManager, benchtool

try:
    parser = argparse.ArgumentParser(description='D3S caller.')
    parser.add_argument('operation', metavar='-op', type=str, help='[W][R][D], Write, Read, Delete')
    parser.add_argument('applicantPath', metavar='--applicantPath', type=str, help='applicantPath')
    parser.add_argument('safebox', metavar='--safebox', type=str, help='TransactionId')
    parser.add_argument('domain', metavar='--domain', type=str, help='RequestId')
    parser.add_argument('login', metavar='--login', type=str, help='WS URL')
    parser.add_argument('wsAuthURL', metavar='--authority', type=str, help='WS URL Authority')
    parser.add_argument('wsStorageURL', metavar='--storage', type=str, help='WS URL Storage')
    parser.add_argument('keystore', metavar='--keystore', type=str, help='Keystore (pem)')
    parser.add_argument('truststore', metavar='--truststore', type=str, help='Trustore (cer)')
    parser.add_argument('--data', metavar='-data', default="WRITE_1234567890", type=str, help='WS URL')
    parser.add_argument('--motivation', metavar='-motivation', type=str, help='tag')
    parser.add_argument('--verbose', metavar='-v', type=bool, help='Print SOAP Messages')
    parser.add_argument('--bench', metavar='-bench', type=bool, help='Bench')
    parser.add_argument('--thread', metavar='-thread', type=int, help='Nb bench thread')
    parser.add_argument('--loop', metavar='-loop', type=int, help='Nb bench loop')
    parser.add_argument('--fileOut', metavar='-fileOut', type=str, help='File out')

    args = parser.parse_args()
    motivation = args.motivation if args.motivation is not None else socket.gethostname() + "#" + str(uuid.uuid4())

    print "D3S Caller "
    print "====================================="
    print "operation\t: ", args.operation
    print "applicantPath\t: ", args.applicantPath
    print "safebox\t\t: ", args.safebox
    print "domain\t\t: ", args.domain
    print "login\t\t: ", args.login
    print "data\t\t: ", args.data
    print "motivation\t: ", motivation
    print "wsAuthURL\t: ", args.wsAuthURL
    print "wsStorageURL\t: ", args.wsStorageURL
    print "keystore\t: ", args.keystore
    print "truststore\t: ", args.truststore, "\n"

    applicantPath = "/USER/" + args.applicantPath
    boxPath = "/SAFEBOX/" + args.safebox

    wr_result = None
    read_result = None
    perm_result = None
    discard_result = None
    del_result = None

    if args.bench == None:
        authCaller = D3SCaller.D3SAuthorityCaller(args.keystore, args.truststore, args.wsAuthURL, args.verbose)
        stoCaller = D3SCaller.D3SStorageCaller(args.keystore, args.truststore, args.wsStorageURL, args.verbose)
        secretMgr = D3SManager.D3SSecretManager(authCaller, stoCaller)
        metadatas = secretMgr.buildPasswordMetadatas(args.login, args.domain)
        depositPath = "/DEPOSIT?_boxPath=" + boxPath + "&appLogin=" + \
                      urllib.quote_plus(args.login) + "&appDomainName=" + urllib.quote_plus(args.domain)

        # Write
        if "W" in args.operation:
            wr_result = secretMgr.write(applicantPath, motivation, boxPath, metadatas, args.data)

        # Read
        if "R" in args.operation:
            read_result = secretMgr.read(applicantPath, motivation, depositPath)

        # Delete
        if "D" in args.operation:
            perm_result = authCaller.setDeletable(applicantPath, motivation, depositPath)
            discard_result = authCaller.discard(applicantPath, motivation, depositPath)
            del_result = secretMgr.delete(applicantPath, motivation, depositPath)

        exitCode = D3SCaller.ppResponse(wr_result, read_result, perm_result, discard_result, del_result, args.data,
                                        args.fileOut)

        print "\nList SSL sessions:"
        print "\tAuthority \t", uuid.uuid4(), "=>", authCaller.getpeercert()
        print "\tStorage \t", uuid.uuid4(), "=>", stoCaller.getpeercert()
        sys.exit(exitCode)

    else:
        print "thread\t\t: ", args.thread
        print "loop\t\t: ", args.loop

        threads = []
        for x in range(0, args.thread):
            threads.append(
                D3SCaller.bench(x, args.loop, args.keystore, args.truststore, args.wsAuthURL, args.wsStorageURL,
                                args.operation, applicantPath, motivation, boxPath, args.login, args.domain, args.data)
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
