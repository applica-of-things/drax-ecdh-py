import time

class TimeWatch():

    _instance = None
    interval = 0
    currentInterval = 0
    callingTimes = 0

    def __new__(cls):
        if cls._instance is None:
            print('Creating the object')
            cls._instance = super(TimeWatch, cls).__new__(cls)
            # Put any initialization here.
        return cls._instance

    def start(self):
        self.currentInterval = time.time()
        self.callingTimes += 1

    def stop(self):
        self.interval = self.interval + (time.time()-self.currentInterval)
        self.currentInterval = 0

    def getInfo(self):
        return self.interval, self.callingTimes