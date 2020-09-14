/*  -------------------------------------------------------------------
 *  Test_FHE_op.cpp
 *
 *  Author: Duplantis Chen
 *  Date: Mar 24, 2018
 *  Email: novachanginn@163.com
 *  -------------------------------------------------------------------
 */

#include <iostream>
#include "FHE_op.h"
using namespace std;

int main()
{
	// Coefficients of FHE
	long m = 0;          
	// p is a prime, we define a negative E[x]>p/2, its real value is x=D{E[x]}-p.
	long p = 2147483647; 
	long r = 1;
	long L = 16;
	long c = 3;
	long w = 64;
	long d = 0;
	long k = 128;
	long s = 0;

	m = FindM(k, L, c, p, d, s, 0);

	FHEcontext context(m, p, r);
	buildModChain(context, L, c);
	ZZX G = context.alMod.getFactorsOverZZ()[0];
	
	// Key generation
	FHESecKey secretKey(context);
	const FHEPubKey& publicKey = secretKey;
	secretKey.GenSecKey(w);
	
	long a = 50, b = -25;

	// Encryption and decryption
	Ctxt Ea = FHE_Enc(a, publicKey);
	Ctxt Eb = FHE_Enc(b, publicKey);
	cout << "a = " << FHE_Dec(Ea, p, secretKey) << endl;
	cout << "b = " << FHE_Dec(Eb, p, secretKey) << endl;

	// Addition
	Ctxt sum = FHE_Add(Ea, Eb);
	cout << "a + b = " << FHE_Dec(sum, p, secretKey) << endl;

	// Subtraction
	Ctxt sub = FHE_Sub(Ea, Eb, publicKey);
	cout << "a - b = " << FHE_Dec(sub, p, secretKey) << endl;

	// Multiplication
	Ctxt mul = FHE_Mul(Ea, Eb, p, secretKey);
	cout << "a * b = " << FHE_Dec(mul, p, secretKey) << endl;

	// Division
	Ctxt div = FHE_Div(Ea, Eb, p, publicKey, secretKey);
	cout << "a / b = " << FHE_Dec(div, p, secretKey) << endl;

	return 0;
}
