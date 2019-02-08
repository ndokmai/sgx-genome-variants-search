float dot_prod(float* x, float *y, int n_) {
	double res = 0.0;
	size_t i = 0;
	for (; i <= n_ - 4; i += 4) {
        	res += (x[i] * y[i] +
			x[i + 1] * y[i + 1] +
			x[i + 2] * y[i + 2] +
			x[i + 3] * y[i + 3]);
	}
	for (; i < n_; i++)
		res += x[i] * y[i];
	return (float) res;
}

void matrix_vector_mult(float **mat, float *vec, float *result, int rows, int cols) { 
	/* In matrix form: result = mat * vec. */
	for (size_t i = 0; i < rows; i++)
		result[i] = dot_prod(mat[i], vec, cols);
}
