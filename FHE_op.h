/*  -------------------------------------------------------------------
 *  FHE_op.h
 *  4 basic operations (+,-,*,/) and a more accurate encryption and
 *  decryption for one number (based on HElib)
 *
 *  Author: Nova Chan
 *  Date: Mar 24, 2018
 *  Email: novachanginn@163.com
 *  -------------------------------------------------------------------
 */

#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>
#include <NTL/lzz_pXFactoring.h>
#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"

#include <cassert>
#include <cstdio>
#include <iostream>
using namespace std;

/*  FHE_Enc() - FHE encryption for one number
 *  Change the number into a vector used for correct decryption,
 *  because the a0...an is represented as:
 *  	f(x) = a0*(x^n) + a1*(x^(n-1)) + ... + a(n-1)*x + an*(x^0)
 *  and the last consecutive zeros will be omitted.
 *  For example : D{E[(0 0 2 2)]} → (0 0 2 2)
 *                D{E[(2 2 0 0)]} → (2 2) 
 *                D{E[(0 0 0 0)]} → () 
 *  The omitted 0 causes an error in basic operations, 
 *  so we add another non-zero number and form a vector to ensure the correctness.
 */
Ctxt FHE_Enc(long num, const FHEPubKey& publicKey)
{
	Ctxt Enc(publicKey);
	Vec<ZZ> v;
	v.SetLength(2);
	v[0] = num;
	v[1] = 1;
	publicKey.Encrypt(Enc, to_ZZX(v));
	return Enc;
}

/*  FHE_Dec() - FHE decryption for one number
 *  Extract the ptxt[0] and adjust it to the correct value.
 */
long FHE_Dec(Ctxt ctxt, long p, const FHESecKey& secretKey)
{
	long Dec;
	ZZX ptxt;
	secretKey.Decrypt(ptxt, ctxt);
	conv(Dec, ptxt[0]);
	if (Dec > p/2)
		Dec -= p;
	return Dec;
}


//  FHE_Add() - FHE addition E[a+b]
Ctxt FHE_Add(Ctxt Ea, Ctxt Eb)
{
	Ctxt ctSum = Ea;
	ctSum += Eb;
	return ctSum;
}

//  FHE_Mul() - FHE multiplication E[a*b]
Ctxt FHE_Mul(Ctxt Ea, Ctxt Eb, long p, const FHESecKey& secretKey)
{
	// if a or b is 0, return E[0].
	if (FHE_Dec(Ea, p, secretKey) == 0)
		return Ea;
	else if (FHE_Dec(Eb, p, secretKey) == 0)
		return Eb;
	else
	{
		Ctxt ctMul = Ea;
		ctMul *= Eb;
		return ctMul;
	}
}


//  FHE_Sub() - FHE subtraction E[a-b]
Ctxt FHE_Sub(Ctxt Ea, Ctxt Eb, const FHEPubKey& publicKey)
{
	// sub = b*(-1)+a
	Ctxt minus1 = FHE_Enc(-1, publicKey);
	Ctxt ctSub = Eb;
	ctSub *= minus1;
	ctSub += Ea;
	return ctSub;
}


// FHE_Div() - FHE division E[a/b]
Ctxt FHE_Div(Ctxt Ea, Ctxt Eb, long p,
			const FHEPubKey& publicKey, const FHESecKey& secretKey)
{
	// A complicative version using iterative subtraction
	long quotient = 0;  // Initialize quotient as 0
	ZZX ptMul, ptMul2, ptSub, ptSum, ptEa, ptEb;

	/* Way of thinking（Denote numerator and denominator as a and b）：
	 * 1. b=0: "Error: Invalid Denominator."(We set the result as 0 temporarily in order to return a value)
	 * 2. a=0: Return E[0]
	 * 3. a≠0 and b≠0: Determine whether a and b are all positive(/negative) by (a*b>0)?
	 *    3-1. Y: Break the loop when a=0
	 *            Or else {
	 *				sub=a-b
	 *				if (sub*a>0 which means |a|>|b|) quotient++ and a=sub
	 *				else break the loop
	 *			  }
	 *    3-2. N: Break the loop when a=0
	 *            Or else {
	 *				sum=a+b (because a and b have different signs)
	 *				if (sum*a>0 which means |a|>|b|) quotient--(the result is a negative) and a=sum
	 *				else break the loop
	 *			  }        
	 */
	
	bool positive = true;
	long EaDec = FHE_Dec(Ea, p, secretKey);
	if (EaDec < 0) positive = false;
	if (EaDec == 0) return Ea;
	long EbDec = FHE_Dec(Eb, p, secretKey);
	if (EbDec == 0) 
	{
		cout << "Error: Invalid Denominator." << endl;
		Ctxt ctDiv = FHE_Enc(0, publicKey);
		return ctDiv;
	}
	else {
		long MulDec = FHE_Dec(FHE_Mul(Ea, Eb, p, secretKey), p, secretKey);
		
		if(MulDec >= 0)
		{
			while (1)
			{
				long EaDec = FHE_Dec(Ea, p, secretKey);
				if (EaDec == 0) break;
				else
				{
					Ctxt ctSub = FHE_Sub(Ea, Eb, publicKey);
					long sub = FHE_Dec(ctSub, p, secretKey);
					if (sub >= 0 && positive || sub <= 0 && !positive)
					{
						Ea = ctSub;
						quotient ++;
					}
					else break;
				}
			}
		}
		 
		else 
		{
			while (1)
			{
				long EaDec = FHE_Dec(Ea, p, secretKey);
				if (EaDec == 0) break;
				else
				{
					Ctxt ctSum = FHE_Add(Ea, Eb);
					long temp = FHE_Dec(FHE_Mul(ctSum, Ea, p, secretKey), p, secretKey);
					if (temp >= 0)
					{
						Ea = ctSum;
						quotient --;
					}
					else break;
				}
			}
		}
		Ctxt ctDiv = FHE_Enc(quotient, publicKey);
		return ctDiv;
	}
	
	// A brief version using plaintext division
	/*
	long EaDec = FHE_Dec(Ea, p, secretKey);
	long EbDec = FHE_Dec(Eb, p, secretKey);
	if (EaDec == 0) return Ea;
	if (EbDec == 0) return Eb;
	return FHE_Enc(EaDec/EbDec, publicKey);
	*/
}