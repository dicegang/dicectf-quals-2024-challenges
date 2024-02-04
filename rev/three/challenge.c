# include <stdio.h>
# include <stdint.h>

# define REGIONS 13

//   0
// 3   1
//   2

int left[6]  = {0, 0, 0, 1, 1, 2};
int right[6] = {1, 2, 3, 2, 3, 3};

int dis[4] = {-1, 0, 1, 0};
int djs[4] = {0, 1, 0, -1};

uint64_t regions[REGIONS] = {
    15, 1052720, 57536,
    33948160, 470289408, 3772776448,
    565179041447936, 515396075520, 216455356602122240,
    865830222501511168, 263882790666240, 1168684103302643712,
    16176929861514821632
};

int key[32] = {
    4, 7, 11, 0, 32, 9, 13, 28,
    6, 21, 13, 13, 5, 31, 22, 20,
    3, 33, 7, 34, 14, 5, 31, 7,
    23, 18, 15, 11, 16, 9, 22, 7
};

int hit_region(int i, int j) {
    for (int k = 0; k < REGIONS; k++) {
        if (regions[k] & ((uint64_t) 1 << (i * 8 + j))) {
            return k;
        }
    }
    return -1;
}

int read_input(char *buf, int *result) {
    for (int i = 0; i < 32; i++) {
        if (buf[i] == '\0') return 0;

        int v;
        if ('a' <= buf[i] && buf[i] <= 'z') {
            v = buf[i] - 'a';
        } else if ('0' <= buf[i] && buf[i] <= '9') {
            v = buf[i] - '0' + 26;
        } else return 0;

        v = (v + key[i]) % 36;

        int left = v / 6;
        int right = v % 6;
        result[i * 2] = left;
        result[i * 2 + 1] = right;
    }
    return 1;
}

int check_grid(int *grid) {
    int counts[REGIONS] = {0};

    int i = 0, j = 0, di = -1, dj = 0;

    int region = hit_region(i, j);
    int count = 0;

    // we double iterate to make sure that each region is properly counted
    // (the first region could be undercounted if (0, 0) is in the middle of a
    // path)
    for (int k = 0; k < 128; k++) {
        // 1. check we are in bounds
        if (i < 0 || i >= 8 || j < 0 || j >= 8) return 0;

        int l = left[grid[i * 8 + j]];
        int r = right[grid[i * 8 + j]];
        int dil = dis[l];
        int djl = djs[l];
        int dir = dis[r];
        int djr = djs[r];

        // 2. get the next direction
        //    this is the one that is not negative of the current direction
        //    if neither is negative then the grid is invalid
        if (di == -dil && dj == -djl) {
            di = dir;
            dj = djr;
        } else if (di == -dir && dj == -djr) {
            di = dil;
            dj = djl;
        } else {
            return 0;
        }

        // 3. update the region counter
        //    if we took consecutive steps in the same region, we increment it
        //    otherwise we reset it
        int new_region = hit_region(i, j);

        if (new_region == -1 && region == -1) {
        } else if (new_region == region) {
            count++;
            if (count > 3) return 0;
        } else {
            counts[region] = counts[region] > count ? counts[region] : count;
            count = 1;
        }

        // 4. step to the next cell
        i += di;
        j += dj;
        region = new_region;

        // 5. check if we've looped too early
        //    this doesn't matter if we've already taken 64 non-looping steps
        //    so we can continue if k is sufficiently large
        if (k >= 63) continue;
        if (i == 0 && j == 0) return 0;
    }

    // check that each region was visited by a path of length 3
    for (int i = 0; i < REGIONS; i++) {
        if (counts[i] != 3) return 0;
    }

    return 1;
}

int main() {
    int grid[64] = {0};

    printf("flag: ");
    fflush(stdout);

    char buf[64];
    char input[33] = {0};

    fgets(buf, 64, stdin);
    if (sscanf(buf, "dice{%32s%[}]", input, buf) != 2) {
        printf("invalid input\n");
        return 1;
    }

    if (!read_input(input, grid)) {
        printf("invalid characters\n");
        return 1;
    }

    if (!check_grid(grid)) {
        printf("incorrect!\n");
        return 1;
    }

    printf("correct!\n");
}
