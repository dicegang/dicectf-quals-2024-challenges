
from dataclasses import dataclass
import json

@dataclass
class Lam:
    arg: any
    body: any

    def __repr__(self):
        return f'(λ{self.arg}.{self.body})'
    
@dataclass
class App:
    func: any
    arg: any

    def __repr__(self):
        return f'({self.func} {self.arg})'
    
@dataclass
class Marker:
    pass


ALPH = 'abcdefghijklmnopqrstuvwxyz'
def varname(n):
    z = ''
    while True:
        z += ALPH[n % len(ALPH)]
        n //= len(ALPH)
        
        if n == 0:
            break
    return z

def link(net, a, b):
    if a[0] in net:
        net[a[0]][a[1]] = b
    if b[0] in net:
        net[b[0]][b[1]] = a

def unlink(net, ptr):
    other = net[ptr[0]][ptr[1]]
    if ptr == net[other[0]][other[1]]:
        net[ptr[0]][ptr[1]] = ptr
        net[other[0]][other[1]] = other
        
def enter(net, a):
    return net[a[0]][a[1]]
        
def new(net, t):
    c = net['_curr']
    net['_curr'] += 1
    net[c] = [(c,0),(c,1),(c,2),t]
    return c
    
def annihilate(net, i, i2):
    link(net, enter(net, (i,1)), enter(net, (i2,1)))
    link(net, enter(net, (i,2)), enter(net, (i2,2)))
    
def duplicate(net, i, i2):
    p = new(net, net[i2][3])
    q = new(net, net[i2][3])
    r = new(net, net[i][3])
    s = new(net, net[i][3])
    link(net, (r,1), (p,1))
    link(net, (s,1), (p,2))
    link(net, (r,2), (q,1))
    link(net, (s,2), (q,2))
    link(net, (p,0), enter(net, (i,1)))
    link(net, (q,0), enter(net, (i,2)))
    link(net, (r,0), enter(net, (i2,1)))
    link(net, (s,0), enter(net, (i2,2)))

def step(net, i, i2) -> bool:
    if net[i][3] == net[i2][3]:
        annihilate(net, i, i2)
    else:
        duplicate(net, i, i2)

    for s in range(3):
        unlink(net, (i, s))
        unlink(net, (i2, s))

    del net[i]
    if i2 in net:
        del net[i2]

    return True


def reduce(net, max_steps=None):
    net['_curr'] = max([k for k in net if type(k) is int]) + 1
    
#     while True:
#         done = True
#         for i in net:
#             if i == 0 or type(i) is str:
#                 continue

#             other = net[i][0]
#             if net[other[0]][0] == (i,0):
#                 step(net, i, other[0])
#                 done = False
#                 break
        
#         if done:
#             break
    
    
    
    warp = []
    exit = []
    nxt = enter(net, (0,1))
    prev = None
    back = None
    rwts = 0
    
    while nxt[0] != 0 or len(warp) > 0:
        if nxt[0] == 0:
            nxt = enter(net, warp.pop(-1))
        prev = enter(net, nxt)
        if nxt[1] == 0 and prev[1] == 0:
            back = enter(net, (prev[0], exit.pop(-1)))
            step(net, prev[0], nxt[0])
            nxt = enter(net, back)
            rwts += 1
            if max_steps is not None and rwts >= max_steps:
                return
        elif nxt[1] == 0:
            warp.append((nxt[0], 2))
            nxt = enter(net, (nxt[0], 1))
        else:
            exit.append(nxt[1])
            nxt = enter(net, (nxt[0], 0))


def decompile(net):
    def dec(net, ptr, vrs, dup_exit):
        a,b,c,t = net[ptr[0]]

        if t == 0:
            # lambda
            match ptr[1]:
                case 0:
                    # Lam
                    name = varname(len(vrs)+1)
                    vrs.append(((ptr[0],1), name))
                    body = dec(net, c, vrs, dup_exit)
                    vrs.pop(-1)
                    return Lam(name, body)
                case 1:
                    # Var
                    
                    for v in vrs[::-1]:
                        if v[0] == ptr:
                            return v[1]
                    return 'unk'
                case 2:
                    # App
                    arg = dec(net, b, vrs, dup_exit)
                    func = dec(net, a, vrs, dup_exit)
                    return App(func, arg)
        else:
            match ptr[1]:
                case 0:
                    # from top
                    slot = dup_exit.pop(-1)
                    t = dec(net, net[ptr[0]][slot], vrs, dup_exit)
                    dup_exit.append(slot)
                    return t
                case _:
                    # from bottom
                    dup_exit.append(ptr[1])
                    t = dec(net, a, vrs, dup_exit)
                    dup_exit.pop(-1)
                    return t
    
    p = enter(net, (0,1))
    
    try:
        out = dec(net, p, [], [])
    except RecursionError:
        out = '<loop>'
    return out


count = 1
def compile_lam(term):
    global count
    count = 1
    def comp(term, net, origin, lams, vr):
        global count
        match term:
            case Lam(arg, body):
                lam = new(net, 0)
                if not arg in lams:
                    lams[arg] = []
                lams[arg].append(lam) # most recent
                vr[lam] = []
                body = comp(body, net, (lam, 2), lams, vr)
                lams[arg].pop(-1)
                
                link(net, (lam,2), body)
                
                if len(vr[lam]) == 1:
                    # link direct
                    link(net, (lam,1), vr[lam][0])
                elif len(vr[lam]) > 1:
                    # duplicate nodes
                    prev = (lam,1)
                    for i in range(len(vr[lam])-1):
                        dup = new(net, count)
                        count += 1
                        link(net, (dup,0), prev)
                        link(net, (dup,1), vr[lam][i])
                        prev = (dup,2)
                        
                    # last link
                    link(net, prev, vr[lam][-1])
                
                return (lam,0)
            case App(func, arg):                
                app = new(net, 0)
                
                v_func = comp(func, net, (app,0), lams, vr)
                v_arg = comp(arg, net, (app,1), lams, vr)
                
                link(net, (app,0), v_func)
                link(net, (app,1), v_arg)
                
                return (app, 2)
            case Marker():
                print('Marker invoked from', origin)
                return (-1,-1)
            case t:
                lam = lams[t][-1]
                vr[lam].append(origin)
                return (-1,-1)
    
    net = {
        '_curr': 1,
        0: [(0,2),(0,1),(0,0),0]
    }
    root = comp(term, net, (-2,-2), {}, {})
    link(net, root, (0,1))
    return net




Zero = Lam('f', Lam('x', 'x'))
One = Lam('f', Lam('x', App('f', 'x')))
Succ = Lam('n', Lam('f', Lam('x', App('f', App(App('n', 'f'), 'x')))))
Plus = Lam('m', Lam('n', Lam('f', Lam('x', App(App('m', 'f'), App(App('n', 'f'), 'x'))))))
Mult = Lam('m', Lam('n', Lam('f', App('m', App('n', 'f')))))
Pow = Lam('b', Lam('e', App('e', 'b')))

def plus(a,b):
    return App(App(Plus, a), b)

def mul(a,b):
    return App(App(Mult, a), b)

def exp(a,b):
    return App(App(Pow, a), b)

def make_num(n):
    num = One
    for i in range(n-1):
        num = App(Succ, num)
    return num

def make_num(n):
    num = App('f', 'x')
    for i in range(n-1):
        num = App('f', num)
    return Lam('f', Lam('x', num))

T = Lam('a', Lam('b', 'a'))
F = Lam('a', Lam('b', 'b'))
ITE = Lam('p', Lam('a', Lam('b', App(App('p', 'a'), 'b'))))
IsZero = Lam('n', App(App('n', Lam('x', F)), T))

Pred = Lam('n', Lam('f', Lam('x',
    App(App(App('n',
        Lam('g', Lam('h', App('h', App('g', 'f'))))
    ),
        Lam('u', 'x')  
    ),
        Lam('u', 'u')
    )
)))

Sub = Lam('m', Lam('n', App(App('n', Pred), 'm')))

def sub(a,b):
    return App(App(Sub,a),b)

Leq = Lam('m', Lam('n', App(IsZero, sub('m', 'n'))))

def leq(a,b):
    return App(App(Leq,a),b)

Pair = Lam('x', Lam('y', Lam('f', App(App('f', 'x'), 'y'))))
First = Lam('p', App('p', T))
Second = Lam('p', App('p', F))
Nil = Lam('x', T)
Empty = Lam('p', App('p', Lam('x', Lam('y', F))))

And = Lam('p', Lam('q', App(App('p', 'q'), 'p')))

def land(a,b):
    return App(App(And,a),b)

Eq = Lam('m', Lam('n', land(leq('m','n'), leq('n','m'))))

def eq(a,b):
    return App(App(Eq,a),b)

def make_pair(a, b):
    return App(App(Pair, a), b)
    
def make_list(items):
    lst = Nil
    for item in items[::-1]:
        lst = make_pair(item, lst)
    return lst

def num_list(nums):
    return make_list([make_num(x) for x in nums])

def ite(cond,t,f):
    return App(App(App(ITE, cond), t), f)

def index(lst,n):
    for i in range(n):
        lst = App(Second, lst)
    return App(First, lst)

def multi_and(cond):
    z = T
    for c in cond:
        z = land(z, c)
    return z

# --------------

# Build the challenge
flag = b'dice{int3racti0n_c0mbin4t0rs_:)}'

import random
random.seed(1)

order = list(range(len(flag)))
random.shuffle(order)
constraints = []

for i in range(0, len(flag)-1):
    oa,ob = order[i:i+2]
    a = flag[oa]
    b = flag[ob]
    
    if a > b:
        constraints.append((oa,ob,a-b))
    else:
        constraints.append((ob,oa,b-a))

def build(a,b,diff):
    if diff == 0:
        return eq(index('lst', a), index('lst', b))
    else:
        return eq(sub(index('lst', a), index('lst', b)), make_num(diff))


prog = Lam('lst', multi_and([
    build(*x) for x in constraints
]))
q = App(prog, Marker())
net = compile_lam(q)

print(len(net))
z = net['_curr']
del net['_curr']
open('brain.json', 'w').write(json.dumps(net))

# test brain load
raw = json.load(open('brain.json'))
net = {int(k): [tuple(raw[k][0]), tuple(raw[k][1]), tuple(raw[k][2]), raw[k][3]] for k in raw}

net['_curr'] = z

# Test the list generation

def write_val(net, val, prev):
    a = new(net, 0)
    b = new(net, 0)
    c = new(net, 0)
    d = new(net, 0)
    e = new(net, 0)
    f = new(net, 0)
    g = new(net, 0)
    h = new(net, 0)
    i = new(net, 0)
    link(net,(a,2),(i,0))
    link(net,(a,0),(b,0))
    link(net,(b,2),(c,0))
    link(net,(b,1),(e,1))
    link(net,(c,2),(d,0))
    link(net,(c,1),(f,1))
    link(net,(d,1),(e,0))
    link(net,(d,2),(f,2))
    link(net,(e,2),(f,0))
    link(net,(a,1),(g,0))
    link(net,(g,2),(h,0))
    link(net,(i,2),prev)
    
    p = (g,1)
    q = (h,2)
    
    t = max([net[x][3] for x in net if type(x) is int]) + 1
    
    for k in range(val-1):
        m = new(net, t)
        n = new(net, 0)
        t += 1
        
        link(net,(m,0),p)
        p = (m,2)
        link(net,(n,0),(m,1))
        link(net,(n,2),q)
        q = (n,1)
        
    z = new(net,0)
    link(net,(z,0),p)
    link(net,(z,2),q)
    link(net,(z,1),(h,1))
    
    return (i,1)

def term(net, prev):
    a = new(net, 0)
    b = new(net, 0)
    c = new(net, 0)
    link(net,(a,0),prev)
    link(net,(a,2),(b,0))
    link(net,(b,2),(c,0))
    link(net,(c,2),(b,1))


# net = {
#     '_curr': 1,
#     0: [(0,2),(0,1),(0,0),0]
# }

# out = [2,3,9,4]

# prev = (0,1)
# for i in range(len(out)):
#     prev = write_val(net, out[i], prev)
# term(net, prev)

# # print('try reduce')
# # reduce(net)
# print(len(net))

# print(decompile(net))

# net2 = compile_lam(num_list(out))
# print(len(net2))
# print(decompile(net2))


prev = (1,1)
for i in range(len(flag)):
    prev = write_val(net, flag[i], prev)
term(net, prev)
print(len(net))

print('try reduce')
reduce(net)
print(len(net))

# check for the true/false structure
a = net[0][1]
b = net[a[0]][2]
c = net[b[0]][2]

ok = b[0] != c[0]
print(ok)

print(decompile(net))
