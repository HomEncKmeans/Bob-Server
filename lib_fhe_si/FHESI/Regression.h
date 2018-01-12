#ifndef _REGRESSION_H_
#define _REGRESSION_H_

#include "FHEContext.h"
#include "Plaintext.h"
#include "FHE-SI.h"
#include "Ciphertext.h"
#include <vector>
#include <fstream>

#include "Matrix.h"


bool LoadData(Matrix<ZZ> &rawData, vector<ZZ> &labels,
              unsigned &dim, const string &filename);

double BatchData(vector<vector<Plaintext>> &ptxtData, vector<Plaintext> &ptxtLabels,
             const Matrix<ZZ> &rawData, const vector<ZZ> &labels, const FHEcontext &context);

class Regression {
 public:
  Regression(const FHEcontext &context);

  void AddData(const vector<vector<Plaintext>> &ptxtData, const vector<Plaintext> &ptxtLabels);

  void Clear();

  void Regress(vector<Ciphertext> &theta, Ciphertext &det) const;
  
  FHESIPubKey &GetPublicKey();
  FHESISecKey &GetSecretKey();
  
  vector<Ciphertext> labels;
 private:
  const FHEcontext &context;
 
  FHESISecKey secretKey;
  FHESIPubKey publicKey;
  
  KeySwitchSI keySwitch;
  vector<KeySwitchSI> autoKeySwitch;

  Matrix<Ciphertext> data;
  
  void SumBatchedData(Ciphertext &batchedData) const;
  
  void GenerateNoise(Ciphertext &noiseCtxt) const;
};

void RegressPT(vector<ZZ> &theta, ZZ &det, Matrix<ZZ> &data,
               vector<ZZ> &labels);


#endif
