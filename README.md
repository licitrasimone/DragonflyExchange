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
