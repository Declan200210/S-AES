# S-DES
## 作业报告
#### 1.基本测试
在本关卡中，我们一共进行了三组测试，我们的输入和输出采用四位十六进制数，输入明文和密钥加密后，在密文框内得到密文，输入密文和密钥解密后，在明文框内得到了相同的明文，该关卡测试通过，以下是测试截图。

第一组加密：

![image](第一组加密.png)

第一组解密：

![image](第一组解密.png)

第二组加密：

![image](第二组加密.png)

第二组解密：

![image](第二组解密.png)

第三组加密：

![image](第三组加密.png)

第三组解密：

![image](第三组解密.png)

#### 2.交叉测试
在本关卡中，本组与对照组都采用相同的明文和密钥来进行加密操作，观察生成的密文是否相同，效果如下。

本组加密：

![image](交叉测试1.png)

对照组加密：

![image](交叉测试2.png)

如上图所示，结果有些许差异。

#### 3.扩展功能
在本关卡中，我们输入一个ASCⅡ码字符，然后对其进行加密，将得到的密文再进行解密，得到了输入的ASCⅡ码，本关卡成功，效果如下图。

加密：

![image](ASC加密.png)

解密：

![image](ASC解密.png)

#### 4.多重加密
###### 4.1.双重加密
我们用我们的程序对我们的明文进行两次加密，在第一次加密完成后，换个密钥，再对加密后的密文进行一次加密，该关卡成功通关，以下是效果图：

![image](第一组加密.png)

![image](双重加密.png)

如图所示，明文为6f6b，密文为71e2，密钥为a73b3457。

###### 4.2.中间相遇攻击

###### 4.3.三重加密
我们用我们的程序对我们的明文进行两次加密，在第一次加密完成后，换个密钥，再对加密后的密文进行一次加密，该关卡成功通关，以下是效果图：

![image](第一组加密.png)

![image](双重加密.png)

![image](三重加密.png)

如图所示，明文为6f6b，密文为b266，密钥为a73b3457bc28。

#### 5.封闭测试
根据第四关的结果，我们不难发现，对于随机选择的明密文对，有不止一个key。

因此，我们又通过对一个选定的明文01010001，我们用可用的所有10bit密钥（共1024个）对其进行加密，并统计所出现的重复密文以及重复次数，结果如下图：

![image](封闭测试.png)

## 开发手册
#### 1.加密、解密函数设计
```
// 加密函数
void encrypt(QString plaintext, unsigned short key, QString& ciphertext)
{
    unsigned char nibbles[4];

    // 判断输入是否为两个ASCII码
    if (plaintext.length() == 2) {
        // 将第一个ASCII码转换为nibbles
          convertToNibbles0(plaintext.at(0).unicode(), nibbles);
          // 将第二个ASCII码转换为nibbles
          convertToNibbles0(plaintext.at(1).unicode(), nibbles + 2);
    } else {
        // 输入视为一个16进制字符串，将其转换为unsigned short类型的整数
          unsigned short input = plaintext.toUShort(nullptr, 16);
          // 将该整数转换为nibbles
          convertToNibbles(input, nibbles);

    }

    // 密钥扩展
    unsigned short roundKeys[3];
    expandKey(&key, roundKeys);

    // 轮密钥加
    nibbles[0] ^= (roundKeys[0] >> 12) & 0xF;
    nibbles[1] ^= (roundKeys[0] >> 8) & 0xF;
    nibbles[2] ^= (roundKeys[0] >> 4) & 0xF;
    nibbles[3] ^= roundKeys[0] & 0xF;

    // 轮函数
    substituteNibbles(nibbles, SBox);

    shiftRows(nibbles);

    mixColumns(nibbles, MixMatrix);

    // 轮密钥加
    nibbles[0] ^= (roundKeys[1] >> 12) & 0xF;
    nibbles[1] ^= (roundKeys[1] >> 8) & 0xF;
    nibbles[2] ^= (roundKeys[1] >> 4) & 0xF;
    nibbles[3] ^= roundKeys[1] & 0xF;

    // 轮函数
    substituteNibbles(nibbles, SBox);

    shiftRows(nibbles);
    // 最后一轮密钥加
    nibbles[0] ^= (roundKeys[2] >> 12) & 0xF;
    nibbles[1] ^= (roundKeys[2] >> 8) & 0xF;
    nibbles[2] ^= (roundKeys[2] >> 4) & 0xF;
    nibbles[3] ^= roundKeys[2] & 0xF;
//qDebug()<<nibbles[0]<<nibbles[1]<<nibbles[2]<<nibbles[3];

    if (plaintext.length() == 2) {
        unsigned char asciiCodes[2];
        asciiCodes[0] = combineNibbles(nibbles); // 合并前两个 nibbles
        asciiCodes[1] = combineNibbles(nibbles + 2); // 合并后两个 nibbles

        ciphertext = QString(QChar(asciiCodes[0])) + QString(QChar(asciiCodes[1]));
    } else {// 将 nibbles 转换为十六进制字符串
        QString hexString = QString("%1%2%3%4")
            .arg(nibbles[0], 1, 16)
            .arg(nibbles[1], 1, 16)
            .arg(nibbles[2], 1, 16)
            .arg(nibbles[3], 1, 16);

            ciphertext = hexString;
    }

   // qDebug()<<ciphertext;
}

// 解密函数
void decrypt(QString ciphertext, unsigned short key, QString& plaintext)
{
    unsigned char nibbles[4];
    // 判断输入是否为两个ASCII码
    if (ciphertext.length() == 2) {
        // 将第一个ASCII码转换为nibbles
          convertToNibbles0(ciphertext.at(0).unicode(), nibbles);
          // 将第二个ASCII码转换为nibbles
          convertToNibbles0(ciphertext.at(1).unicode(), nibbles + 2);
    } else {
        // 输入视为一个16进制字符串，将其转换为unsigned short类型的整数
          unsigned short input = ciphertext.toUShort(nullptr, 16);
          // 将该整数转换为nibbles
          convertToNibbles(input, nibbles);

    }

    // 密钥扩展
    unsigned short roundKeys[4];
    expandKey(&key, roundKeys);

    // 最后一轮密钥加
    nibbles[0] ^= (roundKeys[2] >> 12) & 0xF;
    nibbles[1] ^= (roundKeys[2] >> 8) & 0xF;
    nibbles[2] ^= (roundKeys[2] >> 4) & 0xF;
    nibbles[3] ^= roundKeys[2] & 0xF;

    // 逆行位移
    shiftRowsInverse(nibbles);
    // 逆S盒代替
    substituteNibblesInverse(nibbles, InvSBox);

    // 轮函数
    nibbles[0] ^= (roundKeys[1] >> 12) & 0xF;
    nibbles[1] ^= (roundKeys[1] >> 8) & 0xF;
    nibbles[2] ^= (roundKeys[1] >> 4) & 0xF;
    nibbles[3] ^= roundKeys[1] & 0xF;
    mixColumns(nibbles, rMixMatrix);
    shiftRowsInverse(nibbles);
    substituteNibblesInverse(nibbles, InvSBox);


    // 轮密钥加
    nibbles[0] ^= (roundKeys[0] >> 12) & 0xF;
    nibbles[1] ^= (roundKeys[0] >> 8) & 0xF;
    nibbles[2] ^= (roundKeys[0] >> 4) & 0xF;
    nibbles[3] ^= roundKeys[0] & 0xF;

    if (ciphertext.length() == 2) {
        unsigned char asciiCodes[2];
        asciiCodes[0] = combineNibbles(nibbles); // 合并前两个 nibbles
        asciiCodes[1] = combineNibbles(nibbles + 2); // 合并后两个 nibbles

        plaintext = QString(QChar(asciiCodes[0])) + QString(QChar(asciiCodes[1]));
    } else {// 将 nibbles 转换为十六进制字符串
        QString hexString = QString("%1%2%3%4")
            .arg(nibbles[0], 1, 16)
            .arg(nibbles[1], 1, 16)
            .arg(nibbles[2], 1, 16)
            .arg(nibbles[3], 1, 16);
        plaintext = hexString;
    }

}
```

![image](加解密过程.png)

#### 2.密钥扩展函数设计
```
// S-AES密钥扩展函数
void expandKey(const unsigned short* originalKey, unsigned short* roundKeys)
{
    unsigned char keyBytes[2];
    convertToBytes(originalKey[0], keyBytes);
//qDebug()<<originalKey[0]<<keyBytes[0]<<keyBytes[1];
    // 将原始密钥存储在轮密钥中
    roundKeys[0] = originalKey[0];
  //qDebug()<<roundKeys[0];
    // 生成2个额外的轮密钥
    for (int i = 1; i < 3; i++) {
        unsigned char k0;
        g(keyBytes[1],i,&k0);

        keyBytes[0]= keyBytes[0]^k0;

          keyBytes[1]^=keyBytes[0];
        // 生成轮密钥
        quint16 result = (static_cast<quint16>(keyBytes[0]) << 8) | static_cast<quint16>(keyBytes[1]);
         // qDebug()<<(static_cast<quint16>(keyBytes[0]) << 8);

        roundKeys[i] = static_cast<unsigned short>(result);
        //qDebug()<<roundKeys[i];
    }
}
```

其中用得到的相关组件：
```
//g函数
void g(unsigned short input,int i,unsigned char* key )
{
    unsigned char leftHalf = (input >> 4) & 0x0F; // 获取左半部分（高4位）
    unsigned char rightHalf= input & 0x0F; // 获取右半部分（低4位）
    unsigned char result[2];
    result[0] = rightHalf;
    result[1] = leftHalf;

        int row = (leftHalf>> 2) & 0x03;
        int col = leftHalf & 0x03;
       result[1] = SBox[row * 4 + col];
        int row1 = (rightHalf>> 2) & 0x03;
        int col1 = rightHalf & 0x03;
        result[0]  = SBox[row1 * 4 + col1];
    unsigned char byte = ( result[0]  << 4) | result[1]  ;
    byte ^=Rcon[i - 1];
    *key=byte;//qDebug()<<byte;
}

// S盒和逆S盒
const unsigned char SBox[16] = {0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7};
const unsigned char InvSBox[16] = {0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE};
//轮常量
const unsigned char Rcon[10] = {
    0x80, 0x30
};

void convertToBytes(unsigned short value, unsigned char* bytes)
{
    bytes[0] = (value >> 8) & 0xFF;  // 高位字节
    bytes[1] = value & 0xFF;         // 低位字节
}
```

通过以上方法得到第一轮和第二轮加密的扩展密钥。

#### 3.半字节代替函数设计
```
// S盒代替
void substituteNibbles(unsigned char* nibbles, const unsigned char* sBox)
{
    for (int i = 0; i < 4; ++i) {
        int row = (nibbles[i] >> 2) & 0x03;
        int col = nibbles[i] & 0x03;
        nibbles[i] = sBox[row * 4 + col];
    }
}

// 逆S盒代替
void substituteNibblesInverse(unsigned char* nibbles, const unsigned char* invSBox)
{
    for (int i = 0; i < 4; ++i) {
        int row = (nibbles[i] >> 2) & 0x03;
        int col = nibbles[i] & 0x03;
        nibbles[i] = invSBox[row * 4 + col];
    }
}
```

#### 4.行位移函数设计
输入明密文对：
```
// 行位移
void shiftRows(unsigned char* nibbles)
{
    unsigned char temp = nibbles[1];
    nibbles[1] = nibbles[3];
    nibbles[3] = temp;
}

// 逆行位移
void shiftRowsInverse(unsigned char* nibbles)
{
    unsigned char temp = nibbles[3];
    nibbles[3] = nibbles[1];
    nibbles[1] = temp;
}
```

#### 5.列混淆函数设计
```
// 列混淆
void mixColumns(unsigned char* nibbles, const unsigned char* mixMatrix)
{
    unsigned char result[4];

        result[0] = multiply(mixMatrix[1],nibbles[1])^multiply(mixMatrix[0],nibbles[0]);
        result[1] = multiply(mixMatrix[2], nibbles[0])^multiply(mixMatrix[3],nibbles[1]);
        result[2] = multiply(mixMatrix[0],  nibbles[2]) ^multiply(mixMatrix[1], nibbles[3]);
        result[3] = multiply(mixMatrix[2],nibbles[2]) ^ multiply(mixMatrix[3],nibbles[3]);

    for (int i = 0; i < 4; ++i)
        nibbles[i] = result[i];
}
void convertToNibbles0(unsigned short byte, unsigned char* nibbles)
{
    nibbles[0] = (byte >> 4) & 0xF;
    nibbles[1] = byte & 0xF;
}
unsigned char combineNibbles(unsigned char* nibbles)
{
    unsigned char result = 0;
       for (int i = 0; i < 2; i++) {
           result <<= 4;
           result |= nibbles[i];
       }
       return result;
}
```

以下是相关组件实现：
```
// 列混淆的M矩阵
const unsigned char MixMatrix[4] = {0x1, 0x4, 0x4, 0x1};
const unsigned char rMixMatrix[4] = {0x9, 0x2, 0x2, 0x9};

// TODO 实现x^nfx的函数
void x_de_n_fang_cheng_fx(int xfx[4], int a[4]) //* xfx是结果，a是上一步的结果
{
    //! 注意要取模
    //! 既约多项式是 x^4 + x + 1
    //* 保存四次乘法的系数
    if (a[0] == 0)
    {
        for (int i = 0; i < 3; i++)
            xfx[i] = a[i + 1];
    }
    else
    {
        //! 如果乘数首项不为1就需要将 b1x^2+b0x 与 x+1 进行异或
        xfx[1] = a[2];
        xfx[2] = a[3] == 1 ? 0 : 1;
        xfx[3] = 1;
    }
}
// TODO 乘法
int* chengfa(int a[4], int b[4])
{
    //* 储存结果的系数
    int* result = new int[4];
    for (int i = 0; i < 4; i++)
        result[i] = 0;

    //* 记录下x^nfx
    int xfx[4] = { 0 };
    x_de_n_fang_cheng_fx(xfx, a);
    int x2fx[4] = { 0 };
    x_de_n_fang_cheng_fx(x2fx, xfx);
    int x3fx[4] = { 0 };
    x_de_n_fang_cheng_fx(x3fx, x2fx);

    //* 现在需要根据多项式a和b开始异或
    if (b[0] == 1)
        for (int i = 0; i < 4; i++)
            result[i] ^= x3fx[i];
    if (b[1] == 1)
        for (int i = 0; i < 4; i++)
            result[i] ^= x2fx[i];
    if (b[2] == 1)
        for (int i = 0; i < 4; i++)
            result[i] ^= xfx[i];
    if (b[3] == 1)
        for (int i = 0; i < 4; i++)
            result[i] ^= a[i];

    //qDebug()<<result[0]<<result[1]<<result[2]<<result[3]<<"zhongj";
    return result;
}

void reverseArray(int arr[], int n)
{
    for (int i = 0; i < n / 2; i++) {
        qSwap(arr[i], arr[n - 1 - i]);
    }
}
// 将两个 4 位二进制字符相乘，返回结果的 unsigned char
unsigned char multiply(unsigned char a, unsigned char b) {
    // 将输入的二进制字符转换为 QBitArray
    QBitArray bitsA(4);
    for (int i = 0; i <4; i++) {
        bitsA.setBit(i, (a & (1 << i)) != 0);
    }
    QBitArray bitsB(4);
    for (int i = 0; i <4; i++) {
        bitsB.setBit(i, (b & (1 << i)) != 0);
    }

    // 将 QBitArray 转换为 int 数组
    int arrA[4] = { 0 };
    for (int i = 0; i < 4; i++) {
        arrA[i] = bitsA.at(i);
        //qDebug()<< arrA[i]<<"A";
    }
    int arrB[4] = { 0 };
    for (int i = 0; i < 4; i++) {
        arrB[i] = bitsB.at(i);

    }
    reverseArray(arrA, 4);
     reverseArray(arrB, 4);
     for (int i = 0; i < 4; i++) {
        // qDebug()<< arrA[i]<<"A"<<arrB[i]<<"B";

     }
    // 调用上述代码中的乘法函数进行计算
    int* arrResult = chengfa(arrA, arrB);

    // 将计算结果的 int 数组转换为 QBitArray
    QBitArray bitsResult(4);
    for (int i = 0; i < 4; i++) {
        bitsResult.setBit(i, arrResult[i]);
    }
    for (int i = 0; i <  2; i++) {
           bool temp = bitsResult.at(i);
           bitsResult.setBit(i, bitsResult.at(3 - i));
          bitsResult.setBit(3 - i, temp);
       }
    delete[] arrResult;

    // 将计算结果的 QBitArray 转换为 unsigned char
    unsigned char result = 0;
    for (int i = 0; i < 4; i++) {
        if (bitsResult.testBit(i)) {
            result |= (1 << i);
        }
    }
//qDebug()<<result;
    return result;
}
```

#### 6.主程序函数及GUI设计
创建GUI窗口：
```
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QWidget window;
    QVBoxLayout* layout = new QVBoxLayout(&window);

    QFormLayout* formLayout = new QFormLayout();
    QLineEdit* plaintextEdit = new QLineEdit();
    QLineEdit* keyEdit = new QLineEdit();
    QLineEdit* ciphertextEdit = new QLineEdit();
    formLayout->addRow("Plaintext:", plaintextEdit);
    formLayout->addRow("Key:", keyEdit);
    formLayout->addRow("Ciphertext:", ciphertextEdit);
    layout->addLayout(formLayout);

    QPushButton* encryptButton = new QPushButton("加密");
    QPushButton* decryptButton = new QPushButton("解密");
    layout->addWidget(encryptButton);
    layout->addWidget(decryptButton);

    QLabel* statusLabel = new QLabel();
    layout->addWidget(statusLabel);

    QObject::connect(encryptButton, &QPushButton::clicked, [&]() {
        bool ok;
        QString plaintext = plaintextEdit->text();
        unsigned short key = keyEdit->text().toUShort(&ok, 16);
        QString ciphertext;

        encrypt(plaintext, key, ciphertext);

        ciphertextEdit->setText( ciphertext);
        statusLabel->setText("Encryption completed.");
    });

    QObject::connect(decryptButton, &QPushButton::clicked, [&]() {
        bool ok;
        QString ciphertext = ciphertextEdit->text();
        unsigned short key = keyEdit->text().toUShort(&ok, 16);
        QString plaintext;

        decrypt(ciphertext, key, plaintext);

       plaintextEdit->setText( plaintext);
        statusLabel->setText("Decryption completed.");
    });

    window.show();

    return a.exec();
}
```

## 用户指南
#### 简介：
DES（Data Encryption Standard）是一种对称加密算法，它是最早也是最广泛使用的加密标准之一。DES算法适用于对长度为64位的数据块进行加密和解密，使用一个8位的密钥。
DES算法的核心是轮函数和密钥扩展。它采用了分组密码和迭代加密的设计思想，具有较高的安全性和可靠性。

下面是DES算法的简要步骤：

1.密钥生成：从8位输入密钥中经过置换、分割和压缩等操作，生成2个4位的子密钥，用于后续的加密和解密过程。

2.初始置换：将输入的10位明文按照固定的规则进行重新排列和调整，生成初始置换结果。

3.轮函数：DES算法使用2轮迭代加密的方式。每轮的输入包括32位的左半部分和右半部分。右半部分经过扩展运算，与子密钥进行异或运算，然后通过S-盒替换和P-盒置换得到新的右半部分。最后与左半部分进行异或运算得到新的5位输入。

4.轮函数迭代：重复进行2轮轮函数操作。

5.逆初始置换：经过2轮迭代后，将最后的5位左半部分和右半部分交换位置。

6.输出密文：经过逆初始置换后，得到10位的密文输出。

#### 操作流程：
1.打开DES加密/解密程序界面。

![image](图片1.png)

2.在第一行输入框中，输入8位的明文。确保明文只包含0和1。

![image](图片2.png)

3.在第二行输入框中，输入10位的密钥。同样确保密钥只包含0和1。

![image](图片3.png)

4.点击"加密"按钮，程序将会使用DES算法对明文进行加密。

![image](图片4.png)

5.在下方的输入框中，将显示出加密后的8位密文。请复制或记下该密文以备解密操作使用。

![image](图片5.png)

例如下：

![image](图片6.png)

解密过程：

1.在第一行输入框中，输入要解密的8位密文。确保密文只包含0和1。

![image](图片7.png)

![image](图片8.png)

2.在第二行输入框中，输入之前用于加密的10位密钥。

![image](图片9.png)

3.点击"解密"按钮，程序将会使用DES算法对密文进行解密。

![image](图片10.png)

4.在下方的输入框中，将显示出解密后的明文。

![image](图片11.png)

解密界面：

![image](图片12.png)

#### 注意事项：
请注意，加密和解密操作使用的是相同的密钥。确保在解密操作中使用与加密操作相匹配的密钥。

另外，DES算法存在一些安全性问题，例如密钥长度较短，易受到暴力破解等攻击。因此，在实际应用中，DES算法已经逐渐被更为安全和高效的加密算法如AES所取代。

#### 联系作者：
QQ：1322877041  QQ：3230506757
