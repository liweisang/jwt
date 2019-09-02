# -*- coding: utf-8 -*-
#author yb
from jwt.algorithms import get_default_algorithms

import os
import jwt
import time

ALGOMAP = get_default_algorithms()
print ALGOMAP
default_algo = "RS256"

def _encode(claims, keyfile, algo=None):
    if algo is None:
        algo = default_algo
        if algo not in ALGOMAP:
            raise jwt.InvalidAlgorithmError(algo)
        if not isinstance(claims, dict):
            raise TypeError("claims must a dict")
        token_info = jwt.encode(claims, keyfile, algorithm=algo)
        return token_info
now = int(time.time())

c = {
   "iat": now-60,
   "exp": now + 60*60*24,
   "nbf": now-60,
   "sub": "zhangsan",
   "role": "superman",
   "title":"Vgate-test",
   "language":"en"
   
}

key_private="-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA0IeNb6kOIJAFRo1e2HEj9E5OokzsIWWZfgQMo+1Dvm6B/FQ8\nGfrFSXWemZP4Dv2I0zaQBj32vt4dC/PziwOF2lcUqTNi0Vdg5ZneqyCk30vuc2pz\nMN8CZyWR/Em8CNIOnSjdDAmKWBtYfQq0Opz5PAKqK0T0XWYlWu8N/BRYV1vbgXGF\nI8g2YwT6yXiqOTSMGcE3GYDTg4niZcWDr0/96tl2RhZl7sKi2tjltT3ae619oaiM\ninpeNA77GyKA5AJRIe+qFD7cnrNiq2DlhqO4ppYyEd/tPAoSsENAvQjVGXiYSgUm\n/FshQLNKTe6fKQxphWWnVpOhMrxpSdndUauIHQIDAQABAoIBAQCP1S/FWQIZi71X\n0KMe/8sg8/JhGFW3I3Ef7oMZfso/S9H0zdU2xjXWWX6vx9RN4qrBpNzqsUrElEfM\nutO9iwyEcZQasQr0AiUfuWZQ+w89xg4PJdmWV/w8UTnEnsdH/jt+Q3VUnDAEXbhH\nZ16xHxz6O4xMlB9JXO9fLYyj1xSoC8Eu7QYSaicF/Ga8X4xrGOupZQtN61Psk7db\nh/3aM7oA5k2ZqonhDNqcMOmk4WDJOASKCYDCGzDvc9e1h43IsdHzLg6yG4NoYv/H\nPwMjs4Plg8AzcwzlUjx4t/C6RcCJixu8oUPKWlmyplklMAev6BUoVeo270MTZKpU\niX8nIQ+BAoGBAOL6v4W3bEIlvl2hRv4gIR1gzh5Eiy5AL+aIAzBnG0uzgDcXPvTW\nSfIKQLFx/boAO76+sgJN1G0J+69qnV7WNTBrHJ7GxwB6T+VBclunqyy1aagEpxTo\nA8OEtOv1uTB822Quu6LZUa80VS9ndOfkBVDGfgGb2oAIfxTeULzY+55lAoGBAOsw\n60f7y7zf/p53a7ogs8yVMwrFM26f+yjKh84duQhzvUpUDzc4SIKNQBL5uY83o8af\nSZHOIAvhOCgYF9Y7vlfYdr7qjaS2Djk9FgJNBq8vIa3HnTH8dB7EUxXzG5IhiwdY\nlIR0x2mApPyvGu5uAg/LpBrRNYcWfNx9Lub5lKtZAoGBAMIrv6ukPfhYUYHHdfPv\niGSZa7p46JeoUVHlCNVfXvpjlEuMl07cAmYMX0ttOKDlkjaa660M56xf3e8yRW3b\n0aSZ/OHXKmY+PBri4fGGfejBSKFzWXuI/69C14MDsmjIZuZNFDc7saUwH69t0ZSO\ne/2d0C2QJltg6VXw2SC0fowBAoGBAJb3689lHb67ueFWntv3KfLkwsLjGsSkBMCG\nYO45vhBi2trfYnT7t++1Y6/KhQYdnQ9eKAdj3MZDZ5y0+ngWGXSiCnc6cHmOM0si\nnwITF3tUMbYvMARqHM+zDfJE/ymqRmgMwCjWHTrnzQA2Fn9+NeyVt11PdaClGrkd\n0gGJq5jhAoGAXPUStq7CgNdqDUiWm3GBudJ3XUkyKkmqlliPdCJ3Jxyfv99xqybg\nrcUbCYA2Tdwu5uyQfaVkgPPUdo01x9n8IkMy/24Xs9SRlN33GF6xxek/Dk5gKvbN\nzPaUjF9uePjs2/PcVrsKCOZq7Aj1wuVWojkx5td9Udv7/dCVYKW0B3Q=\n-----END RSA PRIVATE KEY-----\n"
print key_private
t = _encode(c, key_private)
print t
print "======================================"
from jwt.algorithms import get_default_algorithms
from jwt.utils import force_bytes
ALGOMAP = get_default_algorithms()
default_algo = "RS256"
def decode(token, keyfile, algo=None):
    """解析token
    token: token字符串
    keyfile: 公钥
    algo: 加密算法,默认RS256
          可用: RS256 RS384 RS512 ES256 ES384 ES521 ES512 PS256 PS384 PS512
    """
    if not token.strip():
        raise jwt.InvalidTokenError("empty token")

    if algo is None:
        algo = default_algo
    try:
        algo = ALGOMAP[algo]
    except:
        raise jwt.InvalidAlgorithmError(algo)
    key = algo.prepare_key(open(keyfile).read())
    print "6666666666666666666",key
    token_info = jwt.decode(force_bytes(token), key=key, verify=True)
    return token_info

content = decode(t,"key.public")
print content
