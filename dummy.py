import numpy as np

def funzione(a, b, c):
    c = a + b

a = np.array([2,3,4])
b = np.array([4,7,8])
c = np.array([1,1,1])
print(c)
funzione(a,b,c)
print(c)

class State:

    val = 0
    
    def __init__(self) -> None:
        pass

    def increment(self):
        self.val += 1

def incrementa(state):
    state.increment()
    state.increment()

s = State()
s.increment()
print(s.val)
incrementa(s)
print(s.val)