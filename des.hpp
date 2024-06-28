#ifndef DES_DIFFERENTIAL_ATTACK_DES_DES_HPP_
#define DES_DIFFERENTIAL_ATTACK_DES_DES_HPP_
#include <bitset>
using namespace std;
typedef bool bit;
typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned long long uint64;

/**
 * http://des.online-domain-tools.com/
 * һ����֤DES�����㷨��������վ
 */

#define MAX_ROUNDS 16

typedef struct DES_sk {
    bit rd_key[16][48 + 1];
} DES_KEY;

#define ENCRYPT 1
#define DECRYPT 0

const int PC1_Box[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
};

const int PC2_Box[48] = {
    14, 17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
};

const int Shift_R[16] = {
    1, 1, 2, 2, 2, 2,2,2,
    1,2,2,2,2,2,2,1
};

//IP�û���
const int IP_Box[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12,4,
    62, 54, 46, 38, 30, 22, 14,6,
    64, 56, 48, 40, 32, 24, 16,8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

//IP���û���
const int RIP_Box[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

//�ֺ�����չ������
const int EP_Box[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

//�ֺ���S��(ͨ��get_sbx()��������)
const int S_Box[8][64] = {
    {
        14, 4, 13, 1, 2, 15, 11, 8,
        3, 10, 6, 12, 5, 9,0,7,
        0, 15, 7, 4, 14, 2, 13, 1,
        10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11,
        15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8,2,4, 9, 1, 7,
        5, 11, 3, 14, 10, 0, 6, 13
    },
    {
        15, 1, 8, 14, 6, 11, 3, 4,
        9, 7, 2, 13,12,0,5, 10,
        3, 13, 4, 7, 15,2,8,14,
        12, 0, 1, 10, 6, 9, 11, 5,
        0, 14,7,11,10,4,13, 1,
        5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10,1,3, 15,4,2,
        11, 6, 7, 12,0,5,14,9
    },
    {
        10, 0, 9, 14, 6, 3, 15, 5,
        1, 13, 12, 7, 11, 4, 2,8,
        13, 7, 0,9,3,4,6,10,
        2, 8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,
        11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,
        4,15,14,3,11,5,2,12
    },
    {
        7,13,14,3,0,6,9,10,
        1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,
        4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,
        15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,
        9,4,5,11,12,7,2,14,
    },
    {
        2,12,4,1,7,10,11,6,
        8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,
        5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,
        15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,
        6,15,0,9,10,4,5,3
    },
    {
        12,1,10,15,9,2,6,8,
        0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,
        6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,
        7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,
        11,14,1,7,6,0,8,13
    },
    {
        4,11,2,14,15,0,8,13,
        3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,
        14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,
        10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,
        9,5,0,15,14,2,3,12,
    },
    {
        13,2,8,4,6,15,11,1,
        10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,
        12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,
        0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,
        15,12,9,0,3,5,6,11
    }
};

//�ֺ���P�û�
const int P_Box[32] = {
    16,7,20,21, 29, 12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
};

//�ֺ���P�����û�
const int RP_Box[32] = {
    9, 17, 23, 31, 13, 28, 2, 18,
    24, 16, 30, 6, 26, 20, 10, 1,
    8, 14, 25, 3, 4, 29, 11, 19,
    32, 12, 22, 7, 5, 27, 15, 21
};

void bits_xor(bit* x, bit* y, bit* z, int n);

int get_sbox(int x, int index);

void expansion(const bit* in, bit* out);

void permutation(const bit* in, bit* out);

void reverse_permutation(const bit* in, bit* out);

void set_key(bit* K, DES_KEY* desKey);

void des_crypt(const bit* p, bit* c, DES_KEY* desKey, int enc);

void des_reduced_crypt(const bit* p, bit* c, DES_KEY* desKey, int rounds, int enc);


#endif //DES_DIFFERENTIAL_ATTACK_DES_DES_HPP_
using namespace std;

void rotate_left(bit* x, int num) {
    bit temp[30];
    if (num == 1) {
        for (int i = 1; i <= 27; i++) temp[i] = x[i + 1];
        temp[28] = x[1];
    }
    else {
        for (int i = 1; i <= 26; i++) temp[i] = x[i + 2];
        temp[27] = x[1];
        temp[28] = x[2];
    }
    for (int i = 1; i <= 28; i++) x[i] = temp[i];
}

void set_key(bit* K, DES_KEY* desKey) {
    bit temp[60], l[30], r[30];
    for (int i = 0; i < 56; i++) temp[i + 1] = K[PC1_Box[i]];
    for (int i = 0; i < MAX_ROUNDS; i++) {
        for (int j = 1; j <= 56; j++) {
            if (j < 29) l[j] = temp[j];
            else r[j - 28] = temp[j];
        }
        rotate_left(l, Shift_R[i]);
        rotate_left(r, Shift_R[i]);
        for (int j = 1; j <= 56; j++) {
            if (j < 29) temp[j] = l[j];
            else temp[j] = r[j - 28];
        }
        for (int j = 0; j < 48; j++) {
            desKey->rd_key[i][j + 1] = temp[PC2_Box[j]];
        }
        /*if (i == 0)
        {
            printf("1roundkey before PC2:");
            string bits = "";
            for (int j = 1; j <= 54; j += 6) {
                for (int k = j; k < j + 6; k++) {
                    bits += '0' + temp[k];
                }
                bits += " ";
            }
            bits += '0' + temp[55];
            bits += '0' + temp[56];
            cout << bits << "\n";
        }
        if (i == 6)
        {
            printf("7roundkey before PC2:");
            string bits = "";
            for (int j = 1; j <= 54; j += 6) {
                for (int k = j; k < j + 6; k++) {
                    bits += '0' + temp[k];
                }
                bits += " ";
            }
            bits += '0' + temp[55];
            bits += '0' + temp[56];
            cout << bits << "\n";
        }
        if (i == 7)
        {
            printf("8roundkey before PC2:");
            string bits = "";
            for (int j = 1; j <= 54; j += 6) {
                for (int k = j; k < j + 6; k++) {
                    bits += '0' + temp[k];
                }
                bits += " ";
            }
            bits += '0' + temp[55];
            bits += '0' + temp[56];
            cout << bits << "\n";
        }*/
    }
}

/**
 * n�������x = y ^ z
 * @param x
 * @param y
 * @param z
 * @param n
 */
void bits_xor(bit* x, bit* y, bit* z, int n) {
    for (int i = 1; i <= n; i++) {
        x[i] = y[i] ^ z[i];
    }
}


/**
 * �ֺ�����չ�û�
 * @param in
 * @param out
 */
void expansion(const bit* in, bit* out) {
    for (int i = 0; i < 48; i++) {
        out[i + 1] = in[EP_Box[i]];
    }
}


/**
 * �ֺ���P�û�
 * @param in
 * @param out
 */
void permutation(const bit* in, bit* out) {
    for (int i = 0; i < 32; i++) {
        out[i + 1] = in[P_Box[i]];
    }
}

/**
 * �ֺ���P�����û�
 * @param in
 * @param out
 */
void reverse_permutation(const bit* in, bit* out) {
    for (int i = 0; i < 32; i++) {
        out[i + 1] = in[RP_Box[i]];
    }
}


/**
 * S��ӳ�亯��
 * @param x 6��������
 * @param index S�еı��
 * @return 4�������
 */
int get_sbox(int x, int index) {
    bitset<6> b(x);
    int p = b[5] * 2 + b[0];
    int q = b[4] * 8 + b[3] * 4 + b[2] * 2 + b[1];
    return S_Box[index][p * 16 + q];
}


static void round_function(bit* r, DES_KEY* desKey, int index) {
    bit epr[50], ans[50];
    expansion(r, epr);
    bits_xor(epr, desKey->rd_key[index], epr, 48);
    for (int i = 1, j = 1, x, y, id; i <= 48; i += 6, j += 4) {
        x = epr[i] * 2 + epr[i + 5];
        y = epr[i + 1] * 8 + epr[i + 2] * 4 + epr[i + 3] * 2 + epr[i + 4];
        id = x * 16 + y;
        x = S_Box[i / 6][id];
        ans[j] = (x >> 3) & 1;
        ans[j + 1] = (x >> 2) & 1;
        ans[j + 2] = (x >> 1) & 1;
        ans[j + 3] = x & 1;
    }
    permutation(ans, r);
}

void des_crypt(const bit* p, bit* c, DES_KEY* desKey, int enc) {
    bit temp[65], l[35], r[35], tt[35];
    for (int i = 0; i < 64; i++) temp[i + 1] = p[IP_Box[i]];
    for (int i = 1; i <= 64; i++) {
        if (i <= 32) l[i] = temp[i];
        else r[i - 32] = temp[i];
    }
    if (enc) {
        for (int i = 0; i < MAX_ROUNDS; i++) {
            for (int j = 1; j <= 32; j++) tt[j] = r[j];
            round_function(r, desKey, i);
            bits_xor(r, l, r, 32);
            for (int j = 1; j <= 32; j++) l[j] = tt[j];
        }
    }
    else {
        for (int i = MAX_ROUNDS - 1; i >= 0; i--) {
            for (int j = 1; j <= 32; j++) tt[j] = r[j];
            round_function(r, desKey, i);
            bits_xor(r, l, r, 32);
            for (int j = 1; j <= 32; j++) l[j] = tt[j];
        }
    }
    for (int i = 1; i <= 64; i++) {
        if (i <= 32) temp[i] = r[i];
        else temp[i] = l[i - 32];
    }
    for (int i = 0; i < 64; i++) c[i + 1] = temp[RIP_Box[i]];
}

void des_reduced_crypt(const bit* p, bit* c, DES_KEY* desKey, int rounds, int enc) {
    bit temp[65], l[35], r[35], tt[35];
    for (int i = 1; i <= 64; i++) temp[i] = p[i];
    for (int i = 1; i <= 64; i++) {
        if (i <= 32) l[i] = temp[i];
        else r[i - 32] = temp[i];
    }
    if (enc) {
        for (int i = 0; i < rounds; i++) {
            for (int j = 1; j <= 32; j++) tt[j] = r[j];
            round_function(r, desKey, i);
            bits_xor(r, l, r, 32);
            for (int j = 1; j <= 32; j++) l[j] = tt[j];
        }
    }
    else {
        for (int i = rounds - 1; i >= 0; i--) {
            for (int j = 1; j <= 32; j++) tt[j] = r[j];
            round_function(r, desKey, i);
            bits_xor(r, l, r, 32);
            for (int j = 1; j <= 32; j++) l[j] = tt[j];
        }
    }
    for (int i = 1; i <= 64; i++) {
        if (i <= 32) temp[i] = r[i];
        else temp[i] = l[i - 32];
    }
    for (int i = 1; i <= 64; i++) c[i] = temp[i];
}