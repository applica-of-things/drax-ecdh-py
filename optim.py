import numpy as np

# NIST Curve P-192 --> Curve B-163:
_p = 6277101735386680763835789423207666416083908700390324961279
_r = 6277101735386680763835789423176059013767194773182842284081
# s = 0x3045ae6fc8422f64ed579528d38120eae12196d5L
# c = 0x3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65L
_b = int(
    remove_whitespace(
        """
    02 0a601907 b8c953ca 1481eb10 512f7874 4a3205fd"""
    ),
    16,
)
_Gx = int(
    remove_whitespace(
        """
    03 f0eba162 86a2d57e a0991168 d4994637 e8343e36"""
    ),
    16,
)
_Gy = int(
    remove_whitespace(
        """
    00 d51fbc6c 71a0094f a2cdd545 b11c5c0c 797324f1"""
    ),
    16,
)

curve_192 = ellipticcurve.CurveFp(_p, -3, _b, 1)
generator_192 = ellipticcurve.PointJacobi(
    curve_192, _Gx, _Gy, 1, _r, generator=True
)


def double_and_add(x, y, exp):
    
    return tmpx, tmpy
