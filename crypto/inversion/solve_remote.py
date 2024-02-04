import pyhelayers
from pwn import *
import numpy as np
import base64
from copy import copy

he_context = pyhelayers.HeaanContext()
he_context.load_from_file("../../../inversion/public.key")
encoder = pyhelayers.Encoder(he_context)

def load_ctxt_from_file(fn):
    cx = encoder.encode_encrypt([0])
    cx.load_from_file(fn)
    return cx

cx = load_ctxt_from_file("x.ctxt")

cy = copy(cx)
cy.multiply_scalar(0.8)
for i in range(4):
    d = copy(cx)
    d.multiply(cy)
    d.add_scalar(-1)
    d.multiply(cy)
    cy.sub(d)

# send data to server to win
data = base64.standard_b64encode(cy.save_to_buffer())

p = remote("mc.ax", 30662)
print(p.recvline().decode())
p.sendline(data)
sleep(1)
print(p.recv().decode())
