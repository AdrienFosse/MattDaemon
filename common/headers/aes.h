#ifndef AES_H
#define AES_H
#define KEY_SIZE 256
#define IV_SIZE 128


class Aes
{
    public:
        Aes();
        Aes(unsigned char *key, unsigned char *IV);
        Aes(const Aes &aes);
        ~Aes();
        Aes &operator=(const Aes &aes);
        unsigned char *_key;
        unsigned char *_IV;
        int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext);
        int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext);
        void handleErrors(void);

    private:


        std::string random_string(size_t length);

};

#endif