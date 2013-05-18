import encdec


def main(*argv):
    try:
        string = argv[0]
        encode_level = int(argv[1])
    except:
        print 'need 2 args, string, encode-level'
    else:
        cracker = encdec.Cracker()
        stack, encoded = cracker.encode(string, encode_level)
        print '|'.join((str(encoder) for encoder in stack)), encoded
        print 
        print 'DECODING'
        print
        cracker.decode(encoded, max_levels=encode_level, min_levels=encode_level)

if __name__ == '__main__':
    import sys
    main(*sys.argv[1:])