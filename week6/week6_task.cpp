
#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;

void AutomaticRescaleDemo(ScalingTechnique scalTech);


class TraceCipherText {
private:
    std::vector<double> original;  //Plaintext로 받았더니 packing되지 않았다는 오류가 나서 벡터로 받았습니다.
    Ciphertext<DCRTPoly> cipher;
    CryptoContext<DCRTPoly> cc;
    PrivateKey<DCRTPoly> secretKey;

public:
    TraceCipherText(std::vector<double> original, const Ciphertext<DCRTPoly> &cipher, CryptoContext<DCRTPoly> cc, const PrivateKey<DCRTPoly> &secretKey)
        : original(original), cipher(cipher), cc(cc), secretKey(secretKey) {}

    void ShowDetail() {
        std::cout << " =========== Show Detail ===========" << std::endl;
        double scale = cipher->GetScalingFactor();

        Plaintext result;
        cc->Decrypt(cipher, secretKey, &result);

        std::cout << "   +  Scale: " << log2(scale) << std::endl;
        std::cout << "   +  Decrypted Result: " << result << std::endl;

        std::cout << "   +  Original : ";
        for (auto i : original) {
            std::cout << i << ", ";
        }
        std::cout << std::endl;
    }

    void Error(){

    }

    TraceCipherText tradd(const TraceCipherText &other) {
        std::cout << " =========== Add =========== " << std::endl;

        auto resultCipher = cc -> EvalAdd(cipher,other.cipher); //암호문끼리 덧셈 후 resultCipher에 저장

        double scale = resultCipher -> GetScalingFactor(); //resultCipher의 scale

        Plaintext add_result; //덧셈결과의 plaintext 타입
        cc->Decrypt(resultCipher, secretKey, &add_result); //암호문 resultCipher을 복호화해서 평문 add_result에 저장
        std::cout << "   +  덧셈 후 Scale  : " << log2(scale) << std::endl;
        std::cout << "   +  Computed Result  : " << add_result << std::endl;

        //암호화하지 않고 계산했을 때 나와야 하는 값
        std::vector<double> result_vector(original.size(),0);
        std::cout << "   +  Expected result  : ";
        for (size_t i = 0; i < original.size(); ++i) {
            result_vector[i] = original[i] + other.original[i];
            std::cout << result_vector[i] << ", ";
        }
        std::cout << std::endl;

        return TraceCipherText(result_vector, resultCipher, cc, secretKey); //암호화된 덧셈결과 반환
    }

    TraceCipherText trmult(const TraceCipherText &other) {
        std::cout << " =========== Multiply =========== " << std::endl;

        auto resultCipher = cc -> EvalMult(cipher,other.cipher); //암호문끼리 덧셈 후 resultCipher에 저장

        double scale = resultCipher -> GetScalingFactor(); //resultCipher의 scale

        Plaintext mult_result; //곱셈결과의 plaintext 타입
        cc->Decrypt(resultCipher, secretKey, &mult_result); //암호문 resultCipher을 복호화해서 평문 add_result에 저장
        std::cout << "   +  곱셈 후 Scale  : " << log2(scale) << std::endl;
        std::cout << "   +  Computed Result  : " << mult_result << std::endl;

        //암호화하지 않고 계산했을 때 나와야 하는 값
        std::vector<double> result_vector(original.size(),0);
        std::cout << "   +  Expected result : ";
        for (size_t i = 0; i < original.size(); ++i) {
            result_vector[i] = original[i] * other.original[i];
            std::cout << result_vector[i] << ", ";
        }
        std::cout << std::endl;

        return TraceCipherText(result_vector, resultCipher, cc, secretKey); //암호화된 곱셈결과 반환
    }
};


int main(int argc, char* argv[]) {
   
    AutomaticRescaleDemo(FLEXIBLEAUTO);


    return 0;
}

void AutomaticRescaleDemo(ScalingTechnique scalTech) {
   
    if (scalTech == FLEXIBLEAUTO) {
        std::cout << std::endl << std::endl << std::endl << " ===== FlexibleAutoDemo ============= " << std::endl;
    }
    else {
        std::cout << std::endl << std::endl << std::endl << " ===== FixedAutoDemo ============= " << std::endl;
    }

    uint32_t batchSize = 8;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(50);
    parameters.SetScalingTechnique(scalTech);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters); //암호 컨텍스트를 설정하고 생성하는 역할. 암호화, 복호화, 키 생성 등 다양한 암호 연산 수행

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Input
    std::vector<double> x = {3.0, 3.01, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07};
    std::vector<double> x2 = {2.0, 2.01, 2.02, 2.03, 2.04, 2.05, 2.06, 2.07};

    Plaintext ptxt        = cc->MakeCKKSPackedPlaintext(x);
    Plaintext ptxt2        = cc->MakeCKKSPackedPlaintext(x2);

    std::cout << "Input x: " << ptxt << std::endl;
    std::cout << "Input x2: " << ptxt2 << std::endl;

    auto c = cc->Encrypt(ptxt, keys.publicKey);
    auto c2 = cc->Encrypt(ptxt2, keys.publicKey);

    TraceCipherText ct1(x, c, cc, keys.secretKey);
    TraceCipherText ct2(x2, c2, cc, keys.secretKey);


    std::cout << "x 세부사항" << std::endl;

    ct1.ShowDetail();

    std::cout << "x2 세부사항" << std::endl;
    ct2.ShowDetail();

    std::cout << "\nx + x2\n" << std::endl;
    TraceCipherText add_ct1_ct2 = ct1.tradd(ct2);

    std::cout << "\nx * x2\n" << std::endl;
    TraceCipherText mult_ct1_ct2 = ct1.trmult(ct2);

   
   
}





