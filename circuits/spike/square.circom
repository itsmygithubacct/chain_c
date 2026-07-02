pragma circom 2.0.0;

// B1 toolchain spike: prove knowledge of x with x*x == out (out public).
template Square() {
    signal input x;
    signal output out;
    out <== x * x;
}
component main = Square();
