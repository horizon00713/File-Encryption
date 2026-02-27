#include "System.h"
#include <iostream>
#include <fstream>
#include <stdlib.h>

using namespace std;

int main() {
    // 全局实体初始化
    TA ta("Authority");
    TA fakeTa("Fake_TA");

    Client Alice("Alice");
    Client Bob("Bob");
    Client Oscar("Oscar");

    // 【修复核心】：声明为指针，先不装载。等拿到证书再装载！
    Sys* ensys = NULL;    // 发件人终端：Bob
    Sys* desys = NULL;    // 收件人终端：Alice

    string msgFile = "message.txt";
    string plainFile = "plaintext.txt";

    // 预置一份绝密文件
    ofstream out(msgFile);
    out << "Hello Alice! This is a top secret message from Bob. Do not tell anyone!";
    out.close();

    bool isInit = false; // 记录是否已经颁发证书
    string aliceCert;    // 存储 Alice 的证书

    bool isEnd = false;
    while (!isEnd) {
        cout << "\n=========================================================" << endl;
        cout << "       文件加密安全传输系统       " << endl;
        cout << "=========================================================" << endl << endl;

        cout << "  [ 基础设施建设 ] " << endl;
        cout << "    1. 启动 PKI 认证中心 " << endl << endl;

        cout << "  [ 安全通信链路 ] " << endl;
        cout << "    2. 演示正常安全传输  " << endl << endl;

        cout << "  [ 主动防御演练 ] " << endl;
        cout << "    3. 拦截测试：防范身份伪造  " << endl;
        cout << "    4. 拦截测试：防范密文篡改  " << endl << endl;

        cout << "  [ 系统控制 ] " << endl;
        cout << "    0. 安全退出终端 " << endl;
        cout << "---------------------------------------------------------" << endl;

        cout << "  >>> 请输入操作指令 [0-4]: ";
        int choice;
        cin >> choice;
        cout << endl;

        switch (choice) {
        case 1:
            cout << "  >>> [系统初始化] 正在启动国家级根证书授权中心(TA)... " << endl;
            Alice.callCertificate(ta);
            Bob.callCertificate(ta);
            Oscar.callCertificate(ta);

            // 【修复核心】：拿到了证书，有了公私钥，现在正式装载进系统！
            if (ensys != NULL) delete ensys;
            if (desys != NULL) delete desys;
            ensys = new Sys(Bob, ta);
            desys = new Sys(Alice, ta);

            aliceCert = desys->client.getCertificate();
            isInit = true;
            cout << "  [OK] TA 机构已成功为网络用户颁发合法数字证书！ " << endl;
            break;

        case 2:
            if (!isInit) { cout << "  [警告] 请先执行步骤 1 颁发证书！ " << endl; break; }
            cout << "\n  >>> 场景一：正常的安全传输 (Bob -> Alice) <<< " << endl;
            cout << "  【剧情背景】Bob 准备向 Alice 发送一份绝密文件。Bob 首先获取并验证了 Alice 的证书，随后启动混合加密... \n" << endl;

            cout << "  [Bob] 正在验证 Alice 的证书... " << endl;
            if (ensys->varify(aliceCert)) {
                cout << "  [Bob] 证书验证通过，开始混合加密文件... " << endl;
                EncInfo info = ensys->encrypt(msgFile, aliceCert);

                cout << "\n  [Alice] 收到密文包，开始解密文件... " << endl;
                desys->decrypt(info, plainFile);
            }
            break;

        case 3:
            if (!isInit) { cout << "  [警告] 请先执行步骤 1 颁发证书！ " << endl; break; }
            cout << "\n  >>> 场景二：黑客攻击 (伪造证书) <<< " << endl;
            cout << "  【剧情背景】黑客 Oscar 企图发动中间人攻击。他自己生成了一对密钥，并用一个野鸡机构伪造了证书... \n" << endl;

            cout << "  [Oscar] 正在向 Alice 发送伪造的证书... " << endl;
            {
                Client FakeBob("Bob");
                FakeBob.callCertificate(fakeTa);
                string fakeCert = FakeBob.getCertificate();

                cout << "  [Alice] 收到证书，正在向权威机构 TA 申请核验... " << endl;
                if (!desys->varify(fakeCert)) {
                    cout << "  [系统防御成功] ERROR: 证书非权威机构颁发，底层签名解析失败，拒绝建立连接！ " << endl;
                }
            }
            break;

        case 4:
            if (!isInit) { cout << "  [警告] 请先执行步骤 1 颁发证书！ " << endl; break; }
            cout << "\n  >>> 场景三：黑客攻击 (密文在传输途中被篡改) <<< " << endl;
            cout << "  【剧情背景】Bob 再次发送加密文件。黑客 Oscar 潜伏在路由器节点截获了密文，并恶意修改了一个字节！\n" << endl;

            cout << "  [Bob] 重新生成加密文件并发送... " << endl;
            {
                EncInfo tampered_info = ensys->encrypt(msgFile, aliceCert);

                cout << "\n  [Oscar] 拦截成功！恶意翻转了密文中的某个字节... " << endl;
                if (tampered_info.c1.length() > 10) {
                    tampered_info.c1[10] = tampered_info.c1[10] ^ 0xFF;
                }

                cout << "  [Alice] 收到被篡改的密文，尝试解密... " << endl;
                desys->decrypt(tampered_info, plainFile);
            }
            break;

        case 0:
            isEnd = true;
            cout << "  >>> 安全终端已关闭。 " << endl;
            break;

        default:
            cout << "  [错误] 无效的指令！ " << endl;
            break;
        }

        if (!isEnd) {
            cout << "\n---------------------------------------------------------" << endl;
            cout << " 操作执行完毕。按回车键返回终端主界面... ";
            cin.ignore(1024, '\n');
            if (cin.peek() == '\n') cin.get();
            system("cls");
        }
    }

    // 释放内存
    if (ensys != NULL) delete ensys;
    if (desys != NULL) delete desys;

    return 0;
}