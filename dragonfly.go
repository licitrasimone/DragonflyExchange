package dragonfly

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"math/bits"
	r "math/rand"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

type Point struct {
	X int
	Y int
}

type curve struct {
	a int
	b int
	p int
	q int
}

type Msg struct {
	Mac_address string
	Scalar      int
	Element     Point
}

type Device struct {
	Name        string //my name Device
	Password    string //shared password
	Mac_address string //my mac_address Device
	Curve       curve  //shared elliptic curve
	Point       Point  //generated Point with hash
	Key         int    //key generated

	Private int   //random private number
	Scalar  int   //my scalar number
	Element Point //my element Point genereted with Point

	Oth_macaddress string
	Oth_scalar     int
	Oth_element    Point

	PKM []byte
}

func P256() curve {
	/*Secp256k1*/
	a, _ := strconv.ParseInt("0000000000000000000000000000000000000000000000000000000000000000", 16, 64)
	b, _ := strconv.ParseInt("0000000000000000000000000000000000000000000000000000000000000007", 16, 64)
	q, _ := strconv.ParseInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16, 64)
	return curve{a: int(a), b: int(b), p: 37, q: int(q)}
}

/*
Ordinamento dei mac address
*/
func ordermac(m1 string, m2 string) string {
	if m1 > m2 {
		return m1 + m2
	} else {
		return m2 + m1
	}
}

/*
https://en.wikipedia.org/wiki/Euler%27s_criterion
Computes Legendre Symbol.
*/
func is_quadratic(val int, p int) bool {

	return mod(int(math.Pow(float64(val), math.Floor(float64(p-1)/2))), p) == 1
}

/*
Trovare un punto valido sulla curva ellittica mediante una stinga
See algorithm in https://tools.ietf.org/html/rfc7664
in section 3.2.1
*/
func get_Point(mac1, mac2 string, d Device) Point {
	k := 40
	found := 0
	i := 1
	var x, y int
	var Point Point
	var hash hash.Hash

	for i <= k {
		s := ordermac(mac1, mac2) + string(d.Password) + strconv.Itoa(i)
		hash = sha256.New()
		hash.Write([]byte(s))
		//fmt.Printf("Hash : %x\n", hash.Sum(nil))

		n := bits.Len(uint(d.Curve.p)) + 64

		kdf := pbkdf2.Key(hash.Sum(nil), []byte("Dragonfly Exchange"), 4500, n, sha256.New)
		//fmt.Printf("kdf : %x\n", kdf)

		seed := mod(convert_kdf(kdf), (d.Curve.p-1)) + 1
		if is_quadratic(curve_equation(seed, d.Curve), d.Curve.p) {
			found = 1
			x = seed
		}

		i++
	}
	if found == 0 {
		fmt.Println("No valid Point found after", k, "iterations")
	} else {
		y = tonelli_shanks(curve_equation(x, d.Curve), d.Curve.p)

		Point.X = x
		Point.Y = y
	}

	return Point
}

/*
Funzione che serve per convertire la stringa KDF in un intero.
*/
func convert_kdf(kdf []byte) int {
	var nowVar uint32

	nowBuffer := bytes.NewReader(kdf)
	binary.Read(nowBuffer, binary.BigEndian, &nowVar)

	return int(nowVar)
}

/*
In the Commit Exchange, both parties commit to the creation of in a single key.
Devices generate a number called a scalar and a number called an e element
they exchange them with each other to generate a common / shared secret.
To brute force, an attacker has to figure out how many times we "jumped"
on the elliptical curve. The number of hops is the secret d, the private key.
*/
func (d *Device) Commit_exchange(mac2 string) {
	po := get_Point(d.Mac_address, mac2, *d)
	d.Point = po

recalc:
	private := (r.Int() % ((d.Curve.p - 1) - 2 + 1)) + 2
	mask := (r.Int() % ((d.Curve.p - 1) - 2 + 1)) + 2

	scalar := mod((private + mask), d.Curve.q)

	/*If scale is less than two, private and mask MUST be thrown away and regenerated.
	The elements are generated, the mask is no longer needed and MUST be
	immediately destroyed.*/
	if scalar < 2 {
		goto recalc
	}

	element := op_scalar(mask, po, d.Curve)
	element = inverse_Point(element, d.Curve.p)
	//fmt.Println("el in", element)

	d.Private = private
	d.Scalar = scalar
	d.Element = element
}

/*
Function that calculates a token starting from well-known data such as the scalar element and the private key.
The token is a sha256 key generated from the private key generated through
multiplication and sum on the elliptic curves that generate us a valid point, scalar and element of the two devices that
establish the connection and the mac address of the device.
This token will then be exchanged between devices for the actual calculation of a shared key.
*/
func (d *Device) Shared_secret(other_scalar int, other_element Point, other_mac string) []byte {

	var token hash.Hash

	d.Oth_scalar = other_scalar
	d.Oth_element = other_element
	d.Oth_macaddress = other_mac

	if valid_Point(other_element, (*d).Curve) {

		z := op_scalar(other_scalar, (*d).Point, (*d).Curve)
		zz := sum_Points(other_element, z, (*d).Curve)
		k := op_scalar((*d).Private, zz, (*d).Curve)

		d.Key = int(k.X)

		str := strconv.Itoa(d.Key) + strconv.Itoa(d.Scalar) +
			strconv.Itoa(other_scalar) + strconv.Itoa(d.Element.X) + strconv.Itoa(other_element.X) + d.Mac_address

		token = sha256.New()
		token.Write([]byte(str))

		return token.Sum(nil)
	} else {
		fmt.Println("not valid Point.")
		return []byte("")
	}
}

/*
In the confirm exchange, both parties confirm that they have derived the
same secret, and therefore have the same password.
The two peers exchange these confirmations and verify the correctness of the other peer's confirmation they receive. If the
confirmation of the other peer is valid, authentication is successful; if the
confirmation from the other peer is invalid, authentication fails.
If authentication fails, all ephemeral state created as part of the
particular execution of the Dragonfly exchange MUST be irreparably destroyed.
If authentication fails, mk can be exported as
authenticated and secret key that can be used by another protocol, such as IPsec, to protect other data
Pairwise Master Key (PMK) where PMK = H (k | scal (AP1) + scal (AP2) mod q)
*/
func (d *Device) Confirm_exchange(token_rcv []byte) bool {

	var confirm, pmk hash.Hash

	str := strconv.Itoa(d.Key) + strconv.Itoa(d.Oth_scalar) + strconv.Itoa(d.Scalar) +
		strconv.Itoa(d.Oth_element.X) + strconv.Itoa(d.Element.X) + d.Oth_macaddress

	confirm = sha256.New()
	confirm.Write([]byte(str))

	//fmt.Printf("%x, %x \n", token_rcv, confirm.Sum(nil))

	if bytes.Equal(token_rcv, confirm.Sum(nil)) {
		s := strconv.Itoa(d.Key) + strconv.Itoa(mod((d.Scalar+d.Oth_scalar), d.Curve.p))
		pmk = sha256.New()
		pmk.Write([]byte(s))

		d.PKM = pmk.Sum(nil)
		return true
	} else {
		fmt.Println("Token are not equal.")
		d.PKM = []byte("")
		return false
	}
}

/*
Equation of the elliptic curve
*/
func curve_equation(x int, c curve) int {
	return mod((pow(x, 3) + (c.a * x) + c.b), c.p)
}

/*
Inverse point -P of point P with elliptic curves y ^ 2 = x ^ 3 + ax + b.
*/
func inverse_Point(po Point, p int) Point {
	if is_origin_Point(po) {
		return po
	} else {
		var newp Point
		newp.X = po.X
		newp.Y = mod((-po.Y), p)
		return newp
	}
}

/*
Function that checks if 2 points are equal
*/
func equal_Points(p1, p2 Point) bool {
	if (p1.X == p2.X) && (p1.Y == p2.Y) {
		return true
	} else {
		return false
	}
}

/*
Determine if we have a valid representation of a point
on our elliptical curve.
We assume that the coordinates x, y are always reduced modulo p,
so you can more easily compare two points (==).
*/
func valid_Point(po Point, c curve) bool {
	if is_origin_Point(po) {
		return true
	} else {
		return (mod(pow(po.Y, 2)-curve_equation(po.X, c), c.p) == 0) &&
			(0 <= po.X && po.X < c.p) && (0 <= po.Y && po.Y < c.p)
	}
}

func orderPoint(p1, p2 Point) (Point, Point) {
	if p2.X < p1.X {
		return p2, p1
	} else {
		return p1, p2
	}
}

/*
Function that follows the sum rule described for
elliptic curves defined on real numbers.
If the points are the same, use the slope of the tangent line. Otherwise, use the slope of the line
between the two points
*/
func sum_Points(p1, p2 Point, c curve) Point {
	p1, p2 = orderPoint(p1, p2)
	if is_origin_Point(p1) { /* P+O = P */
		return p2
	} else if is_origin_Point(p2) { /* P+O = P */
		return p1
	} else if equal_Points(p1, inverse_Point(p2, c.p)) { /*P+(-P) = O*/
		return Point{X: 0, Y: 0}
	} else { /* R = P + Q */
		var lambda int

		if equal_Points(p1, p2) { /* P == Q*/
			lambda = ((3 * pow(p1.X, 2)) + c.a) * inverse_mol(2*p1.Y, c.p)
		} else { /* P != Q*/
			lambda = (p2.Y - p1.Y) * inverse_mol(int(math.Abs(float64(p2.X-p1.X))), c.p)
		}

		lambda = mod(lambda, c.p)

		x := mod(((pow(lambda, 2)) - (p1.X) - (p2.X)), c.p)
		y := mod((((lambda) * (p1.X - x)) - p1.Y), c.p)

		r := Point{X: x, Y: y}
		return r
	}
}

/*
Function that calculates n ^ m, with n, m integers
If m is 0, return 1, otherwise return n times the result of calling pow with n and m-1.
*/
func pow(n, m int) int {
	if m == 0 {
		return 1
	}
	result := n
	for i := 2; i <= m; i++ {
		result *= n
	}
	return result
}

/*
Function that calculates the modulus between two integers
*/
func mod(a, b int) int {
	m := a % b
	if a < 0 && b < 0 {
		m -= b
	}
	if a < 0 && b > 0 {
		m += b
	}
	return m
}

/*
Calculating the multiplicative inverse using
the extended Euclid algorithm
*/
func inverse_mol(val int, p int) int {
	_, x, _ := ext_euclide(val, p)
	return mod(x, p)
}

/*
Extended Euclid's algorithm
https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
Ritorna (g, x, y) t.c. a*x + b*y = g = gcd(x, y)
*/
func ext_euclide(a int, b int) (int, int, int) {
	if a == 0 {
		return b, 0, 1
	} else {
		g, x, y := ext_euclide(b%a, a)
		return g, (y - (int(math.Floor(float64(b)/float64(a))) * x)), x
	}
}

/*
Function that checks if a point p is the origin point (0,0)
If the X and Y coordinates of the Point are both 0, return true, otherwise return false.
*/
func is_origin_Point(p Point) bool {
	if p.X == 0 && p.Y == 0 {
		return true
	}
	return false
}

/*
Algorithm for Point Multiplication
The function takes a scalar and a point on a curve and returns the scalar multiple of the point
https://en.wikipedia.org/wiki/Elliptic_curve_Point_multiplication
*/
func op_scalar(scalar int, po Point, c curve) Point {
	b := strconv.FormatInt(int64(scalar), 2)
	len := bits.Len(uint(scalar))
	t := po
	for i := 1; i < len; i++ {
		t = sum_Points(t, t, c)
		if b[i] == '1' {
			t = sum_Points(t, po, c)
		}
	}
	return t
}

/*
Tonelli–Shanks algorithm
We're trying to find the square root of a number modulo a prime number
https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
*/
func tonelli_shanks(val int, p int) int {
	var b int
	q := p - 1
	s := 0

	for mod(q, 2) == 0 {
		q = int(math.Floor(float64(q) / 2))
		s += 1
	}

	if s == 1 {
		return mod(int(math.Pow(float64(val), math.Floor(float64(p+1)/4))), p)
	}

	var z int
	for z = 2; z < p; z++ {
		if p-1 == legendre(z, p) {
			break
		}
	}

	c := mod(pow(z, q), p)
	r := mod(pow(val, int(math.Floor(float64(q+1)/2))), p)
	t := mod(pow(val, q), p)
	m := s
	t2 := 0
	for mod((t-1), p) != 0 {
		t2 = mod((t * t), p)
		var i int
		for i = 1; i < m; i++ {
			if mod((t2-1), p) == 0 {
				break
			}
			t2 = mod((t2 * t2), p)
		}

		b = mod(pow(c, (1<<(m-i-1))), p)
		r = mod((r * b), p)
		c = mod((b * b), p)
		t = mod((t * c), p)
		m = i
	}

	return r
}

/*
Simbolo di Legendre
https://it.wikipedia.org/wiki/Simbolo_di_Legendre
*/
func legendre(a, p int) int {
	return int(math.Pow(float64(a), math.Floor(float64(p-1)/2))) % p
}
