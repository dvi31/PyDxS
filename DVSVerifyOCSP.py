#!/usr/bin/python2.7
import sys, traceback, argparse
import time, uuid
import DVSCaller, benchtool
import subprocess

try:
    exitCode = 0

    parser = argparse.ArgumentParser(description='DVS caller.')
    parser.add_argument('certificate', metavar='-certificate', type=str, help='Certificate to validate')
    parser.add_argument('issuer', metavar='-issuer', type=str, help='Issuer file')
    parser.add_argument('url', metavar='--url', type=str, help='URL OCSP responder')
    parser.add_argument('--caFile', metavar='-ca', type=str, help='ca-file')
    parser.add_argument('--vaFile', metavar='-va', type=str, help='va-file')

    args = parser.parse_args()

    print "DVS Caller "
    print "====================================="
    print "certificate\t: ", args.certificate
    print "issuer\t\t: ", args.issuer
    print "url\t\t: ", args.url
    print "caFile\t\t: ", args.caFile
    print "vaFile\t\t: ", args.vaFile

    ts = time.time()
    wsTime = time.time() - ts
    cmd = "openssl ocsp -issuer " + args.issuer + " -CAfile " + args.caFile + \
          " -VAfile " + args.vaFile + " -cert " + args.certificate + " -url " + args.url
    result = subprocess.Popen(cmd)
    wsTime = int(wsTime * 1000)

    print '\nExecution Time :', wsTime, " ms\n"

    print result

    sys.exit()


except Exception as e:
    print e
    traceback.print_exc(file=sys.stdout)
    sys.exit(3)
