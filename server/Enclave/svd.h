/* 
 * svdcomp - SVD decomposition routine. 
 * Takes an m * n matrix a and decomposes it into udv, where u,v are
 * left and right orthogonal transformation matrices, and d is a 
 * diagonal matrix of singular values.
 *
 * This routine is adapted from Numerical Recipes by Luke Tierney 
 * and David Betz.
 *
 * Input to dsvd is as follows:
 *   a = mxn matrix to be decomposed, gets overwritten with u
 *   m = row dimension of a
 *   n = column dimension of a
 *   w = returns the vector of singular values of a
 *   v = returns the right orthogonal transformation matrix
 */

#ifndef SVD_H
#define SVD_H

/* Computes sqrt(a^2 + b^2) without destructive underflow or overflow. */
double pythag(double, double);

/* Compute SVD of a. */
int svdcomp(float**, int, int, float*, float**);
int svdcomp_t(float**, int, int, float*, float**);
int svdcomp_a(float**, int, int, float*, float**);

#endif
