import abc

class ScapyServer(abc.ABC):
    # self.thread = Thread(target=self._startService, daemon=True)
    # self._stopper = True

    @abc.abstractmethod
    def start(self):
        pass

    @abc.abstractmethod
    def stop(self):
        pass

    @abc.abstractmethod
    def _start(self):
        pass

    @abc.abstractmethod
    def _startIpTables(self):
        pass

    @abc.abstractmethod
    def _stopIpTables(self):
        pass

    @abc.abstractmethod
    def _endCondition(self, packet):
        pass

    @abc.abstractmethod
    def _startSniffing(self):
        pass
