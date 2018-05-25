from Cryptodome.Random import random as crypto_random

# Invert a point across the y-axis
def invert_point(P, prime):
    if P[0] == None:
        return (None, None)

    return (P[0], -P[1] % prime)

# Used by point_multiply: Add two points on an elliptic curve
def point_add(Q, P, prime, a):
    if P[0] == None:
        return Q
    if Q[0] == None:
        return P
    if Q == invert_point(P, prime):
        return (None, None)

    if P == Q:
        s = ((3*P[0]**2 + a) * pow(2*P[1], prime - 2 , prime)) % prime
    else:
        s = ((Q[1] - P[1]) * pow(Q[0] - P[0], prime - 2, prime)) % prime

    x_r = (s**2 - P[0] - Q[0]) % prime
    y_r = (s * (P[0] - x_r) - P[1]) % prime
    return (x_r, y_r)

def point_multiply(point, generator, prime, a):
    N = generator
    Q = (None, None)
    binary_point = bin(point)[2:]  # Don't count the "0b" at the start
    m = len(binary_point)

    for i in range(m):
        if(binary_point[i] == "1"):
            Q = point_add(Q, N, prime, a)
        N = point_add(N, N, prime, a)
    return Q

def xgcd(b, a):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while a != 0:
        q, b, a = b // a, a, b % a
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return  b, x0, y0

def inv_mod(b, n):
    g, x, _ = xgcd(b, n)
    if g == 1:
        return x % n

params = {'pub': (9797926492537860902298870260518587923407578998272307454966735200272714115776771055424754231243062734972919089366184, 30984737808016614184663879886105660203425868032624265034682524890801932617052349073464318236145517278704523914461894), 'A': 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112316, 'Gener': (26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087, 8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871), 'priv': 31384282940699253806391623889652552980903179111202512121768535601868581148751617320467359856278346842074158944973620, 'Order': 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643, 'Prime': 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319, 'B': 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575}

def ecdsa_test():
    a = params["A"]
    b = params["B"]
    prime = params["Prime"]
    q = params["Order"]
    A = params["Gener"]
    
    d = crypto_random.randint(0, q)    # Private key
    B = point_multiply(d, A, prime, a)
    k_pub = (prime, a, b, q, A, B)
    
    k_e = crypto_random.randint(0, q) # secret ephemeral key
    R = point_multiply(k_e, A, prime, a)
    r = R[0]
    h_m = 0x2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824
    
    s = ((h_m + (d*r) % q) * inv_mod(k_e, q)) % q
    
    # Verify
    assert(s > 1)
    assert(s < q - 1)
    
    w = inv_mod(s, q) % q
    u1 = (w * h_m) % q
    u2 = (w * r) % q
    
    P1 = point_multiply(u1, A, prime, a)
    P2 = point_multiply(u2, B, prime, a)
    P = point_add(P1, P2, prime, a) 
    
    print(R[1])
    print(r)
    print(P[0])
    print(P[1])
    print(s)
    print(P == r)  # This should be true, but it isn't...
                   # From ECDHE, I believe the add and mul functions are correct.
                   # Can't figure out why this isn't workings.
	
ecdsa_test()