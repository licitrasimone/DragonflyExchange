[![Go Reference](https://pkg.go.dev/badge/github.com/licitrasimone/dragonflyexchange.svg)](https://pkg.go.dev/github.com/licitrasimone/dragonflyexchange)

# DragonflyExchange
implementation of Dragonfly Exchange using ECC

The Dragonfly exchange consists of two message exchanges, a "Commit Exchange" in which both sides commit to a single guess of the 
password, and a "Confirm Exchange" in which both sides confirm knowledge of the password.  A side effect of running the Dragonfly
exchange is an authenticated, shared, and secret key whose cryptographic strength is set by the agreed-upon group.

An elliptic curve is defined by an equation in two variables with coefficients, called in this way because they are described by cubic equations similar to those used for the calculation of the circumference of the ellipse.
In general, the cubic equations describing elliptic curves are known as Weierstrass equations, and have the form
𝑦2 + 𝑎𝑥𝑦 + 𝑏𝑦 = 𝑥3 + 𝑐2 + 𝑑𝑥 + 𝑒
Where a, b, c, d, e are real numbers and x, y have real values.
The definition of an elliptic curve also includes the element O, called the point at infinity, which acts as an identity element.

WPA2's Pre-Shared Key (PSK) authentication methodology is replaced by Simultaneous Authetication of Equals (SAE)
SAE expects that the password is not used for the derivation of the Pairwise Master Key (PMK). The derivation of PMK is based on elliptic curve cryptography (ECC) or a special form of ECC on a finite field.
SAE allows mutual authentication regardless of the role played in the communication of the exchange participants. That is, it does not matter who is the client (STA) and who is the access point (AP) and uses Diffie-Hellman (DH) key exchange.

Both access points start compute a hash of a pre-shared password If MAC1> MAC2:

hash = H (MAC1 | MAC2 | Password | i), hash = H (MAC2 | MAC1 | Password | i) where MAC1 and MAC2 are the MAC addresses of the clients and the password is the secret that both parties share.

The password hash is used to calculate a point P = (x, y) on the elliptic curve:
x = (KDF (hash, length) mod (2m-1)) + 1,
y = sqrt (EC (x)),

To calculate the point P, a Key Derivation Function (KDF) is used which extends the length of the hash (up to m bit), the function that defines the elliptic curve EC and the result is taken modulo 2m-1. If the generated point P = (x, y) is not a valid point on the elliptic curve, the counter i is incremented by one and the algorithm is run again.

If the generated point P = (x, y) is a valid point on the elliptic curve, then the two participants choose two random numbers, private and mask, to calculate two new values: a new point Q and a scalar s

scalar = (private + mask) mod r 
element = inverse (mask × P (x, y)) where r is the order of the elliptic curve. 
Also, note that Q contains the x and y values. At this point both participants exchange values and calculate each other K = privateAP1 × (sAP2 × P (x, y)) + QAP2 = privateAP1 × privateAP2 × P (x, y))

Verification of the correctness of the K key calculated by both Access Points is carried out by calculating a token through the application of a bijective function F (x) that maps point K into a single number

k=F(K)
T AP1 = H (k | s AP1| s AP2| Q | F (Q AP1 AP2) | MAC AP1)

The two exchanged tokens are different, but can be calculated by both parties to verify their correctness. In case both participants are able to confirm the correctness of the tokens, then the key k will be used as the Primary Master Key (PMK)
