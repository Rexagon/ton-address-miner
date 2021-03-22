#include <iostream>
#include <cmath>

#include <bip39.h>

// function to add the elements of two arrays
__global__ void add(int n, const float *x, float *y) {
  auto index = blockIdx.x * blockDim.x + threadIdx.x;
  auto stride = blockDim.x * gridDim.x;
  for (auto i = index; i < n; i += stride) {
    y[i] = x[i] + y[i];
  }
}

int main() {
  int N = 1 << 20;  // 1M elements

  float *x, *y;
  cudaMallocManaged(&x, N * sizeof(float));
  cudaMallocManaged(&y, N * sizeof(float));

  // initialize x and y arrays on the host
  for (int i = 0; i < N; i++) {
    x[i] = 1.0f;
    y[i] = 2.0f;
  }

  // Run kernel on 1M elements on the CPU
  int blockSize = 256;
  int numBlocks = (N + blockSize - 1) / blockSize;
  add<<<numBlocks, blockSize>>>(N, x, y);

  cudaDeviceSynchronize();

  std::cout << "Done" << std::endl;

  // Check for errors (all values should be 3.0f)
  float maxError = 0.0f;
  for (int i = 0; i < N; i++) {
    maxError = fmax(maxError, fabs(y[i] - 3.0f));
  }
  std::cout << "Max error: " << maxError << std::endl;

  // Free memory
  cudaFree(x);
  cudaFree(y);

  return 0;
}
