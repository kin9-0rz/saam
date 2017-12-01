import fire

import widget


class Collector(object):
    """A Collector has one Widget, but wants more."""

    def __init__(self):
        self.widget = widget.Widget()
        self.desired_widget_count = 10

    def collect_widgets(self):
        """Returns all the widgets the Collector wants."""
        return [widget.Widget() for _ in range(self.desired_widget_count)]


def main():
    fire.Fire(Collector(), name='collector')


if __name__ == '__main__':
    main()
