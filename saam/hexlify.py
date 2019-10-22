import argparse
import binascii

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-b')
    parser.add_argument('-a')
    parser.add_argument('-u', action='store_true')

    args = parser.parse_args()

    if args.a:
        print(binascii.unhexlify(args.a).decode(errors='ignore'))
    elif args.b:
        h = binascii.hexlify(args.b.encode())
        if args.u:
            print(h.upper().decode(errors='ignore'))
        else:
            print(h.decode(errors='ignore'))
