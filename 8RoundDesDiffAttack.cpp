#include <string.h>
#include <stdio.h>
#include <time.h>
#include <thread>
//#include “mingw.thread.h”
#include <iostream>
#include <vector>
#include <atomic>
#include "eight_attack.hpp"

using namespace std;

DES_KEY desKey;
DES_KEY desKeyAttack;
bit plain[NUM * 2 + 10][64 + 1];
bit cypher[NUM * 2 + 10][64 + 1];
map<uint64, bool> vis;//键-值对
set<int> is_inactive;//集合容器，内部用二叉搜索树实现，存储不为0的s盒编号

/**
 * 2^{18} 的部分密钥比特计数器
 */
int key_count[1 << 18];

/**
 * 最终攻击得到的第 8 轮轮密钥部分比特
 */
int attack_key[48];

void init_inactive(uint32 delta_R5) {
    bit in[32 + 1], out[48 + 1];
    uint32_bits(delta_R5, in);
    expansion(in, out);
    is_inactive.clear();
    for (int i = 1; i <= 48; i += 6) {
        int x = 0;
        for (int j = i; j < i + 6; j++) x = (x << 1) | out[j];
        if (!x) {
            is_inactive.insert(i / 6);
        }
    }
#ifdef PRINT_INACTIVE
    cout << "Attacked S-Box is: ";
    for (auto& val : is_inactive) {
        cout << val + 1 << " ";
    }
    cout << "\n";
#endif
}

void get_plain(uint64 delta_plain) {
    uint64 x;
    srand(time(0));
    for (int i = 0; i < NUM; i++) {//明文对的数量为NUM=150000
        x = 0;
        for (int j = 0; j < 8; j++) {
            x = (x << 8) | (rand() % 256);//得到64位的随机数用作明文输入
        }
        while (vis.count(x) || vis.count(delta_plain ^ x)) {//count返回指定元素出现次数，若有重复则再生成全新的明文对
            x = 0;
            for (int j = 0; j < 8; j++) {
                x = (x << 8) | (rand() % 256);
            }
        }
        vis[x] = vis[delta_plain ^ x] = true;
        uint64_bits(x, plain[i]);//明文对存放在plain中
        uint64_bits(delta_plain ^ x, plain[i + NUM]);
    }
}

void get_cypher() {
    for (int i = 0; i < NUM; i++) {
        des_reduced_crypt(plain[i], cypher[i], &desKey, ATK_ROUNDS, ENCRYPT);//密文通过8轮加密得到，存放在cypher中
        des_reduced_crypt(plain[i + NUM], cypher[i + NUM], &desKey, ATK_ROUNDS, ENCRYPT);
    }
}

void init_attack(uint64 delta_plain, uint32 delta_R5) {
    memset(plain, 0, sizeof(plain));
    memset(cypher, 0, sizeof(cypher));
    vis.clear();
    is_inactive.clear();
    init_inactive(delta_R5);
    get_plain(delta_plain);
    get_cypher();
}


int filter(const bit* delta_B8, const bit* B8, const bit* delta_C8) {
    //    int mul = 1;
    for (int l1 = 1, l2 = 1; l1 <= 48 && l2 <= 32; l1 += 6, l2 += 4) {
        int s_idx = l1 / 6;
        if (!is_inactive.count(s_idx)) continue;//找到活跃S盒
        int in = 0, out = 0, b = 0;
        for (int r1 = l1; r1 < l1 + 6; r1++) {
            in = (in << 1) | delta_B8[r1];//输入差分
            b = (b << 1) | B8[r1];
        }
        for (int r2 = l2; r2 < l2 + 4; r2++) out = (out << 1) | delta_C8[r2];//输出差分
        if (s_xor[s_idx][in][out].empty()) return true;//查看是否是在S盒的差分分布表中，若表中概率为0则是错误对
        //        mul *= s_xor[s_idx][in][out].size();
    }
    return false;
    //    return mul <= threshold;
}

vector<int> possible_key[3];
void dfs(int d, int now) {
    if (d >= 3) {
        key_count[now]++;//dfs求所有可能的密钥的各自的数量

        return;
    }
    for (auto& x : possible_key[d]) {
        dfs(d + 1, (now << 6) | x);
    }
}

int get_attack_box_idx(vector<int>& attack_box, int x) {
    for (int i = 0; i < attack_box.size(); i++) {
        if (attack_box[i] == x) {
            return i;
        }
    }
    return -1;
}

bool attack_box_count(vector<int>& attack_box, int x) {
    for (auto& val : attack_box) {
        if (val == x) {
            return true;
        }
    }
    return false;
}

void eight_attack(uint32 dl5, int pair_id, int& number, vector<int>& attack_box) {
    bit delta_L5[32 + 1];
    uint32_bits(dl5, delta_L5);
    // 获得第 8 轮 S 盒输入差分，右侧的32位bit经过expansion异或
    bit L8[32 + 1], L8_[32 + 1], B8[48 + 1], B8_[48 + 1], delta_B8[48 + 1];
    for (int i = 1; i <= 32; i++) L8[i] = cypher[pair_id][32 + i];
    for (int i = 1; i <= 32; i++) L8_[i] = cypher[pair_id + NUM][32 + i];
    expansion(L8, B8);
    expansion(L8_, B8_);
    bits_xor(delta_B8, B8, B8_, 48);
    // 获得第 8 轮 S 盒输出差分，左侧的32位bit经过逆p置换后异或
    bit delta_R8[32 + 1], delta_C8[32 + 1], in[32 + 1];
    for (int i = 1; i <= 32; i++) {
        delta_R8[i] = cypher[pair_id][i] ^ cypher[pair_id + NUM][i];
    }
    bits_xor(in, delta_L5, delta_R8, 32);
    reverse_permutation(in, delta_C8);

    if (filter(delta_B8, B8, delta_C8)) return;//错误对直接返回
    number++;
    for (int l1 = 1, l2 = 1; l1 <= 48 && l2 <= 32; l1 += 6, l2 += 4) {
        int s_idx = l1 / 6;
        if (!attack_box_count(attack_box, s_idx + 1)) continue;//如果不是要攻击的S盒就返回
        int in_num = 0, out_num = 0, b = 0;
        for (int r1 = l1; r1 < l1 + 6; r1++) {
            in_num = (in_num << 1) | delta_B8[r1];//要攻击的S盒的输入差分
            b = (b << 1) | B8[r1];
        }
        for (int r2 = l2; r2 < l2 + 4; r2++) out_num = (out_num << 1) | delta_C8[r2];//要攻击的S盒的输出差分
        for (auto& x : s_xor[s_idx][in_num][out_num]) {
            int pk_idx = get_attack_box_idx(attack_box, s_idx + 1);//得到具体的要攻击的S盒的序号
            possible_key[pk_idx].emplace_back(x ^ b);//在该S盒的候补密钥数据区添加输入的值B异或所有可能的x值即密钥，只有6位
        }
    }
    dfs(0, 0);//dfs求解各个候补密钥的数量，存放在key_count[now]中，now为18位密钥
    for (int i = 0; i < 3; i++) possible_key[i].clear();//清除候补密钥区的值
}

bool solve(uint64 delta_plain, uint32 delta_L5, uint32 delta_R5, vector<int>& attack_box) {
    init_attack(delta_plain, delta_R5);
    int right_num = 0;
    for (int i = 0; i < NUM; i++) {
        eight_attack(delta_L5, i, right_num, attack_box);
    }
    cout << "right pair number: " << right_num << endl;
    // 寻找最大计数的子密钥部分比特
    int ans = 0, top = 1 << 18, p_key = -1;
    for (int i = 0; i < top; i++) {
        if (key_count[i] > ans) {
            ans = key_count[i];
            p_key = i;
        }
    }
    if (p_key == -1) {
        cout << "attack failed" << endl;
        return false;
    }

    bitset<18> b(p_key);//存放三个s盒的密钥

    for (int i = 2; i >= 0; i--) {
        for (int j = (attack_box[i] - 1) * 6, k = 5; k >= 0; j++, k--) {
            attack_key[j] = b[k];
        }
        b >>= 6;
    }
    return true;
}

void rotate_right(bit* x, int num) {
    bit temp[30];
    if (num == 1) {
        for (int i = 28; i >= 2; i--) temp[i] = x[i - 1];
        temp[1] = x[28];
    }
    else {
        for (int i = 28; i >= 3; i--) temp[i] = x[i - 2];
        temp[1] = x[27];
        temp[2] = x[28];
    }
    for (int i = 1; i <= 28; i++) x[i] = temp[i];
}
bool PC48to56(std::vector<int>& attack_box, int* tmpkey)
{
    //printf("\nPC48to56\n");
    bit rk[60], l[30], r[30];
    bit K[65];
    bit plainattack[65],cyphercorrect[65], cypherattack[65];
    int loss[8] = { 9, 18, 22, 25, 35, 38, 43, 54 };
    memset(rk, 0, sizeof(bit) * 60);
    memset(cypherattack, 0, sizeof(bit) * 65);
    memset(cyphercorrect, 0, sizeof(bit) * 65);
    memset(plainattack, 0, sizeof(bit) * 65);
    for (int i = 0; i < 48; i++)
    {
        rk[PC2_Box[i]] = tmpkey[i];
    }
    /*
    printf("56bitbeforePC2attack:");
    string bits = "";
    for (int j = 1; j <= 54; j += 6) {
        for (int k = j; k < j + 6; k++) {
            int flag1 = 0;
            for (int m = 0; m < 8; m++)
            {
                if (k == loss[m])
                    flag1 = 1;
            }
            if (!flag1)
                bits += '0' + rk[k];
            else
                bits += '?';
        }
        bits += " ";
    }
    bits += '0' + rk[55];
    bits += '0' + rk[56];
    cout << bits << "\n";
    */
    for (int m = 0; m < 1 << 8; m++)
    {
        bit rktmp[60];
        bitset<18> e2EX(m);
        memcpy(rktmp, rk, sizeof(bit) * 60);
        for (int j = 0; j < 8; j++)
        {
            rktmp[loss[j]] = e2EX[7 - j];
        }
        //逆pc2置换
        /*if (m == 0x98)//1001 1000 0100 1100
        {
            printf("8roundkeyattack before PC2:");
            string bits = "";
            for (int j = 1; j <= 54; j += 6) {
                for (int k = j; k < j + 6; k++) {
                    bits += '0' + rktmp[k];
                }
                bits += " ";
            }
            bits += '0' + rktmp[55];
            bits += '0' + rktmp[56];
            cout << bits << "\n";
        }
        */
        for (int i = 0; i < 8; i++)//循环右移
        {

            for (int j = 1; j <= 56; j++)
            {
                if (j < 29) l[j] = rktmp[j];//l[1]-l[28] 从1-28
                else r[j - 28] = rktmp[j];//r[1]-r[28] 从29-56
            }
            rotate_right(l, Shift_R[7-i]);
            rotate_right(r, Shift_R[7-i]);
            for (int j = 1; j <= 56; j++)
            {
                if (j < 29) rktmp[j] = l[j];
                else rktmp[j] = r[j - 28];
            }
            for (int j = 0; j < 48; j++) {
                desKeyAttack.rd_key[i][j + 1] = rktmp[PC2_Box[j]];
            }
            /*if (m == 0x98)
            {
                printf("%dAroundAttackkeybeforepc2:", 7 - i);
                string bits = "";
                for (int j = 1; j <= 54; j += 6) {
                    for (int k = j; k < j + 6; k++) {
                            bits += '0' + rktmp[k];
                    }
                    bits += " ";
                }
                bits += '0' + rktmp[55];
                bits += '0' + rktmp[56];
                cout << bits << "\n";
            }
            */
        }
        //0roundkey after PC1:000001 100110 011011 110111 101001 001100 001001 010000 101010 01
        //1roundkey before PC2 : 000011 001100 110111 101111 010010 011000 010010 100001 010100 10
        //7roundkey before PC2 : 011011 110111 101000 000110 011001 010000 101010 010100 110000 10
        //8roundkey before PC2 : 101111 011110 100000 011001 100101 000010 101001 010011 000010 01
        for (int i = 0; i < 56; i++)
        {
            K[PC1_Box[i]] = rktmp[i + 1];
        }
        set_key(K, &desKeyAttack);
        des_reduced_crypt(plain[10], cyphercorrect, &desKey, ATK_ROUNDS, ENCRYPT);//密文通过8轮加密得到，存放在cypher中
        des_reduced_crypt(plain[10], cypherattack, &desKeyAttack, ATK_ROUNDS, ENCRYPT);//密文通过8轮加密得到，存放在cypher中
        bool tmpflag = 1;
        for (int i = 1; i < 65; i++)
        {
            if (cyphercorrect[i] != cypherattack[i])
            {
                tmpflag = 0;
                break;
            }
        }
        if (tmpflag == 1)
        {
            printf("this is attackkey\n");
            print_rounds_key(&desKeyAttack, 8);
            return true;
        }
    }
    return false;
}

void BruteForce(int start, std::vector<int>& attack_box3, std::atomic<bool>* flag) {
    int tmpkey[48];
    std::memcpy(tmpkey, attack_key, sizeof(int) * 48);
    std::bitset<18> Exnum(start);
    /*printf("attck 18 is: ");
    cout << Exnum << "\n";*/
    for (int i = 2; i >= 0; i--) {
        for (int j = (attack_box3[i] - 1) * 6, k = 5; k >= 0; j++, k--) {
            tmpkey[j] = Exnum[k];
        }
        Exnum >>= 6;
    }
    /*
    cout << "attack key is:"<< endl;
    for (int i = 0; i < 48; i++)
    {
        if (i % 6 == 0)
            printf(" ");
        printf("%x", tmpkey[i]);
    }
    */
    /*if (start == 61766) { 
        std::cout << "Thread found the correct value: " << start << std::endl;
        *flag = true;
    }*/
    if (PC48to56(attack_box3, tmpkey)) {
        *flag=true;
    }
}
void plainnum2accuracy()
{
    std::time_t t = std::time(0);
    init_key(&desKey);
    init_s_xor();
    int  accurycy = 0;
    for (int aoundnum = 0; aoundnum < 1000; aoundnum++)
    {
        memset(attack_key, -1, sizeof(attack_key));
        uint64 delta_plain = 0x405C000004000000ULL;
        uint32 delta_L5 = 0x04000000U;
        uint32 delta_R5 = 0x405C0000U;
        // 第一次攻击 S6, S7, S8 对应的 18 比特轮密钥
        vector<int> attack_box1 = { 6, 7, 8 };
        memset(key_count, 0, sizeof(key_count));
        bool result = solve(delta_plain, delta_L5, delta_R5, attack_box1);
        if (!result) exit(-1);
        // 第二次攻击 S2，S5，S6 对应的 18 比特轮密钥
        vector<int> attack_box2 = { 2, 5, 6 };
        memset(key_count, 0, sizeof(key_count));
        result = solve(delta_plain, delta_L5, delta_R5, attack_box2);
        if (!result) exit(-1);
        // 攻击完成，破解得到 30 比特的第 8 轮轮密钥
        int tmpflag = 1;
        for (int j = 0; j < 48; j++)
        {
            if (attack_key[j] == -1 || desKey.rd_key[ATK_ROUNDS - 1][j + 1] == attack_key[j])
            {

            }
            else
            {
                tmpflag = 0;
            }
        }
        if (tmpflag == 1)
        {
            accurycy++;
        }
    }
    printf("accuracy:%d\n", accurycy);
    printf("Time: %ds\n", (int)(std::time(0) - t));
}
void get_bits(uint32& delta, bit* x) {
    bitset<32> b(delta);
    for (int i = 31, j = 1; i >= 0; i--, j++) {
        x[j] = b[i];
    }
}
void print_bits(bit* a, int n, int per) {
    for (int i = 1; i <= n; i++) {
        cout << a[i];
        if (i % per == 0) {
            cout << " ";
        }
    }
    cout << "\n";
}
struct Frac {
    int x, y; // x / y

    Frac() {
        x = y = 1;
    }

    Frac(int x, int y) {
        this->x = x;
        this->y = y;
        this->reduce();
    }

    int gcd(int a, int b) {
        return b == 0 ? a : gcd(b, a % b);
    }

    void reduce() {
        int g = gcd(x, y);
        x /= g;
        y /= g;
    }

    void multiply(Frac& p) {
        p.reduce();
        this->x *= p.x;
        this->y *= p.y;
        this->reduce();
    }

    void print() {
        cout << x << "/" << y << "\n";
    }
};
void test_possibility() {
    uint32 D1 = 0x04000000U, D2 = 0x40080000U;
    //    uint32 D1 = 0x00540000U, D2 = 0x04000000U;
    bit d1[32 + 1], d2[32 + 1], out[32 + 1], in[48 + 1];
    get_bits(D1, d1);
    get_bits(D2, d2);
    expansion(d1, in);
    print_bits(in, 48, 6);
    reverse_permutation(d2, out);
    print_bits(out, 32, 4);
    init_s_xor();
    //    print_s_xor(1);
    Frac ans;
    for (int i = 1, j = 1; i <= 48 && j <= 32; i += 6, j += 4) {
        int x = 0, y = 0, index = i / 6;
        for (int k = i; k < i + 6; k++) x = (x << 1) | in[k];
        for (int k = j; k < j + 4; k++) y = (y << 1) | out[k];
        if (x == 0) continue;
        if (s_xor[index][x][y].size() > 0) {
            Frac cur(s_xor[index][x][y].size(), 64);
            ans.multiply(cur);
        }
    }
    ans.print();
}

void test_noise() {
    init_s_xor();
    for (int i = 0; i < 8; i++) {
        double p = 0;
        for (int x = 0; x < 64; x++) {
            int sum = 0;
            for (int y = 0; y < 16; y++) {
                if (s_xor[i][x][y].size() != 0) {
                    sum++;
                }
            }
            p += 1.0 * sum / 16;
        }
        printf("S[%d]: %.4lf\n", i, p / 64);
    }
}
void test_stable() {
    int dx = '\x34', dy = '\x03';
    map<pair<int, int>, bool> mp;
    vector<pair<int, int>> ans;
    for (int i = 0; i < 64; i++) {
        int j = i ^ dx;
        if ((get_sbox(i, 0) ^ get_sbox(j, 0)) == dy) {
            if (!mp.count({ i, j }) && !mp.count({ j, i })) {
                mp[{i, j}] = 1;
                mp[{j, i}] = 1;
                ans.push_back({ min(i, j), max(i, j) });
            }
        }
    }
    int x = '\x21';
    for (auto& val : ans) {
        printf("%02X,%02X ", val.first ^ x, val.second ^ x);
    }
    puts("");
}
int main() {
    std::time_t t = std::time(0);
    init_key(&desKey);
    init_s_xor();
    //print_s_xor(0);
    //test_stable();
    //test_possibility();
    test_noise();
    memset(attack_key, -1, sizeof(attack_key));
    uint64 delta_plain = 0x405C000004000000ULL;
    uint32 delta_L5 = 0x04000000U;
    uint32 delta_R5 = 0x405C0000U;
    // 第一次攻击 S6, S7, S8 对应的 18 比特轮密钥
    vector<int> attack_box1 = { 6, 7, 8 };
    memset(key_count, 0, sizeof(key_count));
    bool result = solve(delta_plain, delta_L5, delta_R5, attack_box1);
    if (!result) exit(-1);
    // 第二次攻击 S2，S5，S6 对应的 18 比特轮密钥
    vector<int> attack_box2 = { 2, 5, 6 };
    memset(key_count, 0, sizeof(key_count));
    result = solve(delta_plain, delta_L5, delta_R5, attack_box2);
    if (!result) exit(-1);
    // 攻击完成，破解得到 30 比特的第 8 轮轮密钥
    cout << "\nattack finished: \n";
    cout << "8round key is: ";
    for (int i = 1; i <= 48; i++) {
        cout << desKey.rd_key[ATK_ROUNDS - 1][i];
        if (i % 6 == 0) {
            cout << " ";
         }
    }
    cout << "\nattack key is: ";
    for (int i = 0; i < 48; i++) {
        if (attack_key[i] == -1) {
            cout << "?";
        }
        else {
            cout << attack_key[i];
        }
        if ((i + 1) % 6 == 0) {
            printf(" ");
        }
    }
    puts("");
    
    
    //tmp=std::thread(BruteForce, 61766, std::ref(attack_box3), &flag);
    //tmp.join();
    //BruteForce(61766, std::ref(attack_box3), &flag);
    const int th_cnt = 8;
    std::thread ths[th_cnt];
    std::vector<int> attack_box3 = { 1, 3, 4 };
    std::atomic<bool> flag(false); // 使用 std::atomic<bool> 进行线程安全的操作

    for (int i = 0; i < (1 << 18); i += th_cnt) {
        if (i % 8192 == 0) {
            printf("%.0lf%%\n", i * 100.0 / (1 << 18));
            fflush(stdout);
        }

        for (int j = 0; j < th_cnt; j++) {
            if (i + j < (1 << 18)) { // 确保索引不超出范围
                ths[j] = std::thread(BruteForce, i + j, std::ref(attack_box3), &flag);
                if (i + j == 61766) {
                    printf("61766 thread started\n");
                }
            }
        }

        for (int j = 0; j < th_cnt; j++) {
            if (ths[j].joinable()) { // 检查线程是否可加入
                ths[j].join();
            }
        }

        if (flag.load()) { // 使用 flag.load() 确保正确读取原子变量
            std::cout << "Flag detected, breaking loop." << std::endl;
            break;
        }
    }

    if (flag.load()) {
        std::cout << "BruteForce found the correct value: 61766" << std::endl;
    }
    else {
        std::cout << "BruteForce did not find the correct value." << std::endl;
    }

 
    std::cout << "\nFinished execution" << std::endl;
    printf("Time: %ds\n", (int)(std::time(0) - t));
    return 0;
}
