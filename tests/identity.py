import fire


def identity(arg=None):
    return arg, type(arg)


def main(_=None):
    fire.Fire(identity, name='identity')


if __name__ == '__main__':
    main()
