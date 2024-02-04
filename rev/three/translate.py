# int left[6]  = {0, 0, 0, 1, 1, 2};
# int right[6] = {1, 2, 3, 2, 3, 3};
#
# int di[4] = {-1, 0, 1, 0};
# int dj[4] = {0, 1, 0, -1};
#
# uint64_t regions[REGIONS] = {
#     0b00000000 +
#     0b00000000 << 8 +
#     0b00000000 << 16 +
#     0b00000000 << 24 +
#     0b00000000 << 32 +
#     0b00000000 << 40 +
#     0b00000000 << 48 +
#     0b00000000 << 56,
#
#     0b00000000 +
#     0b00000000 << 8 +
#     0b00000000 << 16 +
#     0b00000000 << 24 +
#     0b00000000 << 32 +
#     0b00000000 << 40 +
#     0b00000000 << 48 +
#     0b00000000 << 56,
#
#     0b00000000 +
#     0b00000000 << 8 +
#     0b00000000 << 16 +
#     0b00000000 << 24 +
#     0b00000000 << 32 +
#     0b00000000 << 40 +
#     0b00000000 << 48 +
#     0b00000000 << 56,
# };

def number(di, dj):
    if di == -1 and dj == 0: return 0
    if di == 0 and dj == 1: return 1
    if di == 1 and dj == 0: return 2
    if di == 0 and dj == -1: return 3

def type_id(left, right):
    if left == 0 and right == 1: return 0
    if left == 0 and right == 2: return 1
    if left == 0 and right == 3: return 2
    if left == 1 and right == 2: return 3
    if left == 1 and right == 3: return 4
    if left == 2 and right == 3: return 5

path = '''
    ---------------------------------
    | xxxxxxxxx | xxxxx | xxxxxxxxx |
    --x-------x---x---x---x-------x--
    | x | xxxxx | x | x | xxxxx | x |
    --x---x-------x---x-------x---x--
    | x | xxxxxxxxx | xxxxxxxxx | x |
    --x---------------------------x--
    | xxxxxxxxxxxxxxxxxxxxx | xxxxx |
    ----------------------x---x------
    | xxxxxxxxxxxxxxxxxxxxx | xxxxx |
    --x---------------------------x--
    | xxxxx | xxxxxxxxxxxxxxxxx | x |
    ------x---x---------------x---x--
    | xxxxx | xxxxxxxxxxxxx | x | x |
    --x-------------------x---x---x--
    | xxxxxxxxxxxxxxxxxxxxx | xxxxx |
    ---------------------------------
'''

bruh = '''
    ---------------------------------
    | xxxxxxxxx | xxxxx | xxxxxxxxx |
    --x-------x---x---x---x-------x--
    | x | xxxxx | x | x | xxxxx | x |
    --x---x-------x---x-------x---x--
    | x | xxxxx | x | xxxxxxxxx | x |
    --x-------x---x---------------x--
    | x | xxxxx | xxxxxxxxxxxxx | x |
    --x---x-------------------x---x--
    | x | xxxxxxxxx | xxxxxxxxx | x |
    --x-----------x---x-----------x--
    | xxxxxxxxx | xxxxx | xxxxxxxxx |
    ----------x-----------x----------
    | xxxxxxxxx | xxxxx | xxxxxxxxx |
    --x-----------x---x-----------x--
    | xxxxxxxxxxxxx | xxxxxxxxxxxxx |
    ---------------------------------
'''

regions = '''
    ---------------------------------
    | 0 | 0 | 0 | 0 | 1 | 1 | 4 | 4 |
    ---------------------------------
    |   | 2 | 3 | 3 | 1 | 4 | 4 | 4 |
    ---------------------------------
    |   | 2 | 2 | 3 | 1 | 5 | 5 | 5 |
    ---------------------------------
    |   | 2 | 3 | 3 | 3 | 5 | 5 | 5 |
    ---------------------------------
    | 6 | 6 | 6 | 7 | 7 | 7 | 7 |   |
    ---------------------------------
    | 8 | 6 | 9 | 9 | a | a | a | a |
    ---------------------------------
    | 8 | 6 | 9 | b | b | b |   | c |
    ---------------------------------
    | 8 | 8 | 9 | 9 | b | c | c | c |
    ---------------------------------
'''

def convert_path(path):
    path = path.strip()
    path = path.split('\n')
    path = [path.strip() for path in path]

    values = []
    for i in range(0, len(path) - 2, 2):
        for j in range(1, len(path[i]), 4):
            window = [
                row[j:j+3]
                for row in path[i:i+3]
            ]
            exits = []
            for di, x in zip([-1, 0, 1], window):
                for dj, y in zip([-1, 0, 1], x):
                    if di == 0 and dj == 0: continue
                    if y == 'x': exits.append(number(di, dj))
            left, right = sorted(exits)
            values.append(type_id(left, right))

    # combine adjacent values
    windowed = []
    for i in range(0, len(values), 2):
        windowed.append(values[i] * 6 + values[i+1])

    return windowed

def to_alphabet(windowed):
    alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join([alphabet[i] for i in windowed])

def to_number(a):
    if a in 'abcdefghijklmnopqrstuvwxyz':
        return ord(a) - ord('a')
    return ord(a) - ord('0') + 26

def convert_regions(path):
    path = path.strip()
    path = path.split('\n')
    path = [path.strip() for path in path]

    regions = {}
    for i in range(0, len(path) - 2, 2):
        for j in range(1, len(path[i]), 4):
            window = [
                row[j:j+3]
                for row in path[i:i+3]
            ]
            number = window[1][1]
            if number == ' ': continue
            number = int(number, 16)
            if number not in regions:
                regions[number] = []
            regions[number].append((i // 2, j // 4))

    return regions

def to_bitmask(regions):
    results = {}
    for number, coords in regions.items():
        bitmask = 0
        for i, j in coords:
            print(number, i, j)
            bitmask |= 1 << (i * 8 + j)
        results[number] = bitmask

    return list(results.values())

result = to_alphabet(convert_path(path))
other = to_alphabet(convert_path(bruh))
print(f'dice{{{result}}}')
print(to_bitmask(convert_regions(regions)))

def find_key(target, current):
    target = map(to_number, target)
    current = map(to_number, current)
    result = []
    for t, c in zip(target, current):
        print(t, c)
        result.append((c - t) % 36)
    return result

def apply_key(key, current):
    result = []
    for k, c in zip(key, current):
        result.append((c - k) % 36)
    return to_alphabet(result)

key = find_key('s0w3ne3daf1a97hat5th1r7y7wo6yte5', result)
print(key)
print(list(map(to_number, result)))
print(apply_key(key, list(map(to_number, other))))
