import abc
import os
import sys


class Subscriber(abc.ABC):

    @abc.abstractmethod
    def notify(self, event):
        print('Got notification! ', event)
