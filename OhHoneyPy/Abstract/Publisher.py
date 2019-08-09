

class Publisher:

    def __init__(self):
        self.subscribers = []

    def publish(self, event):
        for subscriber in self.subscribers:
            subscriber.notify(event)

    def addSubscriber(self, subscriber):
        if subscriber not in self.subscribers:
            self.subscribers.append(subscriber)

