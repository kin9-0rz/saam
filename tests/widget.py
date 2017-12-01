import fire


class Widget(object):

    def whack(self, n=1):
        """Prints "whack!" n times."""
        return ' '.join('whack!' for _ in range(n))

    def bang(self, noise='bang'):
        """Makes a loud noise."""
        return '{noise} bang!'.format(noise=noise)


def main():
    fire.Fire(Widget(), name='widget')


if __name__ == '__main__':
    main()
