grids = [
    15, 1052720, 57536,
    33948160, 470289408, 3772776448,
    565179041447936, 515396075520, 216455356602122240,
    865830222501511168, 263882790666240, 1168684103302643712,
    16176929861514821632
]

# each grid is a 64 bit int
# whether 1 << (i * 8 + j) is in the grid
# denotes whether it's set
# print out these grids in ascii format

for grid in grids:
    for i in range(8):
        for j in range(8):
            print('X' if grid & (1 << (i * 8 + j)) else '.', end='')
        print()
    print()
