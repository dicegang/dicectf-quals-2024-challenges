import pyhelayers
from pwn import *
import numpy as np
import base64
from copy import copy
import tqdm

he_context = pyhelayers.HeaanContext()
he_context.load_from_file("../../../inversion/public.key")
encoder = pyhelayers.Encoder(he_context)

def load_ctxt_from_file(fn):
    cx = encoder.encode_encrypt([0])
    cx.load_from_file(fn)
    return cx

cx = load_ctxt_from_file("x_hard.ctxt")

def fhe_cheby(x, n):
    x = cx
    x2 = copy(x)
    x2.sub(x2)
    x2.add_scalar(1)
    C = [x2, copy(x)]
    for i in tqdm.tqdm(range(2, n)):
        if i%2==0:
            p1 = C[i//2]
            p = copy(p1)
            p.multiply(p)
            p.add(p)
            p.add_scalar(-1)
        else:
            p1 = C[i//2]
            p2 = C[1 + i//2]
            p = copy(p1)
            p.multiply(p2)
            p.add(p)
            p.sub(x)
        C.append(p)
    C = np.array(C)[1::2]
    return C
    

vcoeffs = np.array([1.9830456, -1.9507686, 1.9169458, -1.8846176, 1.8509608, -1.8186045, 1.7852048, -1.7527971, 1.7197406, -1.687323, 1.6546226, -1.6222821, 1.5899507, -1.5577219, 1.5258194, -1.4937496, 1.4622881, -1.4304096, 1.3994993, -1.3677802, 1.3374874, -1.3059613, 1.2763071, -1.2450713, 1.2159937, -1.1851883, 1.1566406, -1.1263335, 1.0983543, -1.0685804, 1.0411706, -1.0119994, 0.98516781, -0.95666428, 0.93034865, -0.90264138, 0.87681753, -0.84994426, 0.82464101, -0.79863445, 0.77383457, -0.74877413, 0.72443742, -0.70039607, 0.67652913, -0.65350384, 0.63015646, -0.60812948, 0.58534219, -0.56429281, 0.54216299, -0.52199448, 0.50059997, -0.48133468, 0.46060207, -0.44235707, 0.4222227, -0.40502803, 0.38547135, -0.3693718])
P = fhe_cheby(cx, 120)

sum = copy(cx)
sum.sub(cx)
for i in range(len(P)):
    t = copy(P[i])
    t.multiply_scalar(vcoeffs[i])
    sum.add(t)
cy = sum
for i in range(2):
    d = copy(cx)
    d.multiply(cy)
    d.add_scalar(-1)
    d.multiply(cy)
    cy.sub(d)

# send data to server to win
data = base64.standard_b64encode(cy.save_to_buffer())

p = remote("mc.ax", 30663)
print(p.recvline().decode())
p.sendline(data)
sleep(1)
print(p.recv().decode())
