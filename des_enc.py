"""
中国海洋大学教务系统运用的DES加密算法的Python版本
"""
import base64
import hashlib
import hmac


def mbase64(str):
    res = base64.encodestring(str)
    return res


def simaple_md5(str):
    m2 = hashlib.md5()
    m2.update(str)
    res = m2.hexdigest()
    return res


def hmac_md5(ekey, data):
    to_enc = simaple_md5(data)
    enc_res = hmac.new(ekey, to_enc, hashlib.md5).hexdigest()
    return enc_res


def rsaEnc(plaintext_text, public_modulus_hex, public_exponent_hex):
    public_modulus = int(public_modulus_hex, 16)
    public_exponent = int(public_exponent_hex, 16)
    # Beware, plaintext must be short enough to fit in a single block!
    plaintext = int(plaintext_text[::-1].encode('hex'), 16)
    ciphertext = pow(plaintext, public_exponent, public_modulus)
    return '%X' % ciphertext  # return hex representation


def base64encode(string):
    base64EncodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    length = len(string)
    i = 0
    out = ""
    while (i < length):
        c1 = ord(string[i]) & 0xff
        i += 1
        if i == length:
            out += base64EncodeChars[c1 >> 2]
            out += base64EncodeChars[(c1 & 0x3) << 4]
            out += "=="
            break
        c2 = ord(string[i])
        i += 1
        if i == length:
            out += base64EncodeChars[c1 >> 2]
            out += base64EncodeChars[((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4)]
            out += base64EncodeChars[(c2 & 0xF) << 2]
            out += "="
            break
        c3 = ord(string[i])
        i += 1
        out += base64EncodeChars[c1 >> 2]
        out += base64EncodeChars[((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4)]
        out += base64EncodeChars[((c2 & 0xF) << 2) | ((c3 & 0xC0) >> 6)]
        out += base64EncodeChars[c3 & 0x3F]
    return out


def utf16to8(string):
    out = ""
    length = len(string)
    for i in range(0, length):
        c = ord(string[i])
        if (c >= 0x0001) and (c <= 0x007F):
            out += string[i]
        elif c > 0x07FF:
            out += chr(0xE0 | ((c >> 12) & 0x0F))
            out += chr(0x80 | ((c >> 6) & 0x3F))
            out += chr(0x80 | ((c >> 0) & 0x3F))
        else:
            out += chr(0xC0 | ((c >> 6) & 0x1F))
            out += chr(0x80 | ((c >> 0) & 0x3F))
    return out


def getKeyBytes(key):
    keyBytes = []
    leng = len(key)
    iterator = int(leng / 4)
    remainder = leng % 4
    i = 0
    for i in range(0, iterator):
        keyBytes.append(strToBt(key[i * 4 + 0:i * 4 + 4]))
        i += 1
    if remainder > 0:
        keyBytes.append(strToBt(key[i * 4 + 0:leng]))
    return keyBytes


def strToBt(str):
    leng = len(str)
    bt = [None] * 64
    if leng < 4:
        for i in range(0, leng):
            k = ord(str[i])
            for j in range(0, 16):
                pow = 1
                for m in range(15, j, -1):
                    pow *= 2
                bt[16 * i + j] = int(k / pow) % 2
        for p in range(leng, 4):
            k = 0
            for q in range(0, 16):
                pow = 1
                for m in range(15, q, -1):
                    pow *= 2
                bt[16 * p + q] = int(k / pow) % 2
    else:
        for i in range(0, 4):
            k = ord(str[i])
            for j in range(0, 16):
                pow = 1
                for m in range(15, j, -1):
                    pow *= 2
                bt[16 * i + j] = int(k / pow) % 2
    return bt


def enc(dataByte, keyByte):
    keys = generateKeys(keyByte)

    ipByte = initPermute(dataByte)
    ipLeft = [None] * 32
    ipRight = [None] * 32
    tempLeft = [None] * 32
    i = 0
    j = 0
    k = 0
    m = 0
    n = 0
    for k in range(0, 32):
        ipLeft[k] = ipByte[k]
        ipRight[k] = ipByte[32 + k]
    for i in range(0, 16):
        for j in range(0, 32):
            tempLeft[j] = ipLeft[j]
            ipLeft[j] = ipRight[j]
        key = [None] * 48
        for m in range(0, 48):
            key[m] = keys[i][m]

        tempRight = xor(pPermute(sBoxPermute(xor(expandPermute(ipRight), key))), tempLeft)
        for n in range(0, 32):
            ipRight[n] = tempRight[n]

    finalData = [None] * 64
    for i in range(0, 32):
        finalData[i] = ipRight[i]
        finalData[32 + i] = ipLeft[i]
    return finallyPermute(finalData)


def generateKeys(keyByte):
    key = [None] * 56
    keys = [None] * 16
    keys[0] = []
    keys[1] = []
    keys[2] = []
    keys[3] = []
    keys[4] = []
    keys[5] = []
    keys[6] = []
    keys[7] = []
    keys[8] = []
    keys[9] = []
    keys[10] = []
    keys[11] = []
    keys[12] = []
    keys[13] = []
    keys[14] = []
    keys[15] = []
    loop = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    for i in range(0, 7):
        k = 7
        for j in range(0, 8):
            key[i * 8 + j] = keyByte[8 * k + i]
            k -= 1

    for i in range(0, 16):
        tempLeft = 0
        tempRight = 0
        for j in range(0, loop[i]):
            tempLeft = key[0]
            tempRight = key[28]
            for k in range(0, 27):
                key[k] = key[k + 1]
                key[28 + k] = key[29 + k]
            key[27] = tempLeft
            key[55] = tempRight
        tempKey = [None] * 48
        tempKey[0] = key[13]
        tempKey[1] = key[16]
        tempKey[2] = key[10]
        tempKey[3] = key[23]
        tempKey[4] = key[0]
        tempKey[5] = key[4]
        tempKey[6] = key[2]
        tempKey[7] = key[27]
        tempKey[8] = key[14]
        tempKey[9] = key[5]
        tempKey[10] = key[20]
        tempKey[11] = key[9]
        tempKey[12] = key[22]
        tempKey[13] = key[18]
        tempKey[14] = key[11]
        tempKey[15] = key[3]
        tempKey[16] = key[25]
        tempKey[17] = key[7]
        tempKey[18] = key[15]
        tempKey[19] = key[6]
        tempKey[20] = key[26]
        tempKey[21] = key[19]
        tempKey[22] = key[12]
        tempKey[23] = key[1]
        tempKey[24] = key[40]
        tempKey[25] = key[51]
        tempKey[26] = key[30]
        tempKey[27] = key[36]
        tempKey[28] = key[46]
        tempKey[29] = key[54]
        tempKey[30] = key[29]
        tempKey[31] = key[39]
        tempKey[32] = key[50]
        tempKey[33] = key[44]
        tempKey[34] = key[32]
        tempKey[35] = key[47]
        tempKey[36] = key[43]
        tempKey[37] = key[48]
        tempKey[38] = key[38]
        tempKey[39] = key[55]
        tempKey[40] = key[33]
        tempKey[41] = key[52]
        tempKey[42] = key[45]
        tempKey[43] = key[41]
        tempKey[44] = key[49]
        tempKey[45] = key[35]
        tempKey[46] = key[28]
        tempKey[47] = key[31]
        switch = {i: [keys[i].append(tempKey[m]) for m in range(0, 48)]}
        switch.get(i)
    return keys


def initPermute(originalData):
    ipByte = [None] * 64
    m = 1
    n = 0

    for i in range(0, 4):

        k = 0
        for j in range(7, -1, -1):
            ipByte[i * 8 + k] = originalData[j * 8 + m]
            ipByte[i * 8 + k + 32] = originalData[j * 8 + n]
            k += 1
        m += 2
        n += 2
    return ipByte


def xor(byteOne, byteTwo):
    xorByte = [None] * len(byteOne)
    for i in range(0, len(byteOne)):
        xorByte[i] = byteOne[i] ^ byteTwo[i]
    return xorByte


def pPermute(sBoxByte):
    pBoxPermute = [None] * 32
    pBoxPermute[0] = sBoxByte[15]
    pBoxPermute[1] = sBoxByte[6]
    pBoxPermute[2] = sBoxByte[19]
    pBoxPermute[3] = sBoxByte[20]
    pBoxPermute[4] = sBoxByte[28]
    pBoxPermute[5] = sBoxByte[11]
    pBoxPermute[6] = sBoxByte[27]
    pBoxPermute[7] = sBoxByte[16]
    pBoxPermute[8] = sBoxByte[0]
    pBoxPermute[9] = sBoxByte[14]
    pBoxPermute[10] = sBoxByte[22]
    pBoxPermute[11] = sBoxByte[25]
    pBoxPermute[12] = sBoxByte[4]
    pBoxPermute[13] = sBoxByte[17]
    pBoxPermute[14] = sBoxByte[30]
    pBoxPermute[15] = sBoxByte[9]
    pBoxPermute[16] = sBoxByte[1]
    pBoxPermute[17] = sBoxByte[7]
    pBoxPermute[18] = sBoxByte[23]
    pBoxPermute[19] = sBoxByte[13]
    pBoxPermute[20] = sBoxByte[31]
    pBoxPermute[21] = sBoxByte[26]
    pBoxPermute[22] = sBoxByte[2]
    pBoxPermute[23] = sBoxByte[8]
    pBoxPermute[24] = sBoxByte[18]
    pBoxPermute[25] = sBoxByte[12]
    pBoxPermute[26] = sBoxByte[29]
    pBoxPermute[27] = sBoxByte[5]
    pBoxPermute[28] = sBoxByte[21]
    pBoxPermute[29] = sBoxByte[10]
    pBoxPermute[30] = sBoxByte[3]
    pBoxPermute[31] = sBoxByte[24]
    return pBoxPermute


def finallyPermute(endByte):
    fpByte = [None] * 64
    fpByte[0] = endByte[39]
    fpByte[1] = endByte[7]
    fpByte[2] = endByte[47]
    fpByte[3] = endByte[15]
    fpByte[4] = endByte[55]
    fpByte[5] = endByte[23]
    fpByte[6] = endByte[63]
    fpByte[7] = endByte[31]
    fpByte[8] = endByte[38]
    fpByte[9] = endByte[6]
    fpByte[10] = endByte[46]
    fpByte[11] = endByte[14]
    fpByte[12] = endByte[54]
    fpByte[13] = endByte[22]
    fpByte[14] = endByte[62]
    fpByte[15] = endByte[30]
    fpByte[16] = endByte[37]
    fpByte[17] = endByte[5]
    fpByte[18] = endByte[45]
    fpByte[19] = endByte[13]
    fpByte[20] = endByte[53]
    fpByte[21] = endByte[21]
    fpByte[22] = endByte[61]
    fpByte[23] = endByte[29]
    fpByte[24] = endByte[36]
    fpByte[25] = endByte[4]
    fpByte[26] = endByte[44]
    fpByte[27] = endByte[12]
    fpByte[28] = endByte[52]
    fpByte[29] = endByte[20]
    fpByte[30] = endByte[60]
    fpByte[31] = endByte[28]
    fpByte[32] = endByte[35]
    fpByte[33] = endByte[3]
    fpByte[34] = endByte[43]
    fpByte[35] = endByte[11]
    fpByte[36] = endByte[51]
    fpByte[37] = endByte[19]
    fpByte[38] = endByte[59]
    fpByte[39] = endByte[27]
    fpByte[40] = endByte[34]
    fpByte[41] = endByte[2]
    fpByte[42] = endByte[42]
    fpByte[43] = endByte[10]
    fpByte[44] = endByte[50]
    fpByte[45] = endByte[18]
    fpByte[46] = endByte[58]
    fpByte[47] = endByte[26]
    fpByte[48] = endByte[33]
    fpByte[49] = endByte[1]
    fpByte[50] = endByte[41]
    fpByte[51] = endByte[9]
    fpByte[52] = endByte[49]
    fpByte[53] = endByte[17]
    fpByte[54] = endByte[57]
    fpByte[55] = endByte[25]
    fpByte[56] = endByte[32]
    fpByte[57] = endByte[0]
    fpByte[58] = endByte[40]
    fpByte[59] = endByte[8]
    fpByte[60] = endByte[48]
    fpByte[61] = endByte[16]
    fpByte[62] = endByte[56]
    fpByte[63] = endByte[24]
    return fpByte


def sBoxPermute(expandByte):
    sBoxByte = [None] * 32
    binary = ""
    s1 = [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]

    s2 = [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]

    s3 = [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]

    s4 = [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]

    s5 = [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]

    s6 = [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]

    s7 = [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]]

    s8 = [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]

    for m in range(0, 8):
        i = 0
        j = 0
        i = expandByte[m * 6 + 0] * 2 + expandByte[m * 6 + 5]
        j = expandByte[m * 6 + 1] * 2 * 2 * 2 + expandByte[m * 6 + 2] * 2 * 2 \
            + expandByte[m * 6 + 3] * 2 + expandByte[m * 6 + 4]

        switch = {0: getBoxBinary(s1[i][j]),
                  1: getBoxBinary(s2[i][j]),
                  2: getBoxBinary(s3[i][j]),
                  3: getBoxBinary(s4[i][j]),
                  4: getBoxBinary(s5[i][j]),
                  5: getBoxBinary(s6[i][j]),
                  6: getBoxBinary(s7[i][j]),
                  7: getBoxBinary(s8[i][j])}
        binary = switch.get(m)
        sBoxByte[m * 4 + 0] = int(binary[0:1])
        sBoxByte[m * 4 + 1] = int(binary[1:2])
        sBoxByte[m * 4 + 2] = int(binary[2:3])
        sBoxByte[m * 4 + 3] = int(binary[3:4])
    return sBoxByte


def getBoxBinary(i):
    binary = ""
    switch = {0: "0000",
              1: "0001",
              2: "0010",
              3: "0011",
              4: "0100",
              5: "0101",
              6: "0110",
              7: "0111",
              8: "1000",
              9: "1001",
              10: "1010",
              11: "1011",
              12: "1100",
              13: "1101",
              14: "1110",
              15: "1111"}
    binary = switch.get(i)
    return binary


def expandPermute(rightData):
    epByte = [None] * 48
    for i in range(0, 8):
        if i == 0:
            epByte[i * 6 + 0] = rightData[31]
        else:
            epByte[i * 6 + 0] = rightData[i * 4 - 1]
        epByte[i * 6 + 1] = rightData[i * 4 + 0]
        epByte[i * 6 + 2] = rightData[i * 4 + 1]
        epByte[i * 6 + 3] = rightData[i * 4 + 2]
        epByte[i * 6 + 4] = rightData[i * 4 + 3]
        if i == 7:
            epByte[i * 6 + 5] = rightData[0]
        else:
            epByte[i * 6 + 5] = rightData[i * 4 + 4]
    return epByte


def bt64ToHex(byteData):
    hex = ""
    for i in range(0, 16):
        bt = ""
        for j in range(0, 4):
            bt += str(byteData[i * 4 + j])
        hex += bt4ToHex(bt)
    return hex


def bt4ToHex(binary):
    switch = {"0000": "0",
              "0001": "1",
              "0010": "2",
              "0011": "3",
              "0100": "4",
              "0101": "5",
              "0110": "6",
              "0111": "7",
              "1000": "8",
              "1001": "9",
              "1010": "A",
              "1011": "B",
              "1100": "C",
              "1101": "D",
              "1110": "E",
              "1111": "F",
              }
    hex = switch.get(binary)
    return hex


def desEnc(data, firstKey, secondKey, thirdKey):
    leng = len(data)
    encData = ""
    if firstKey != None and firstKey != "":
        firstKeyBt = getKeyBytes(firstKey)
        firstLength = len(firstKeyBt)

    if secondKey != None and secondKey != "":
        secondKeyBt = getKeyBytes(secondKey)
        secondLength = len(secondKeyBt)

    if thirdKey != None and thirdKey != "":
        thirdKeyBt = getKeyBytes(thirdKey)
        thirdLength = len(thirdKeyBt)

    if leng > 0:
        if leng < 4:
            bt = strToBt(data)
            if firstKey != None and firstKey != "" and secondKey != None and secondKey != "" and thirdKey != None and thirdKey != "":
                tempBt = bt
                for x in range(0, firstLength):
                    tempBt = enc(tempBt, firstKeyBt[x])

                for y in range(0, secondLength):
                    tempBt = enc(tempBt, secondKeyBt[y])

                for z in range(0, thirdLength):
                    tempBt = enc(tempBt, thirdKeyBt[z])

                encByte = tempBt
            elif firstKey != None and firstKey != "" and secondKey != None and secondKey != "":
                tempBt = bt
                for x in range(0, firstLength):
                    tempBt = enc(tempBt, firstKeyBt[x])

                for y in range(0, secondLength):
                    tempBt = enc(tempBt, secondKeyBt[y])

                encByte = tempBt
            elif firstKey != None and firstKey != "":
                tempBt = bt
                for x in range(0, firstLength):
                    tempBt = enc(tempBt, firstKeyBt[x])
                encByte = tempBt
            encData = bt64ToHex(encByte)
        else:
            iterator = int(leng / 4)
            remainder = leng % 4
            for i in range(0, iterator):
                tempData = data[i * 4 + 0:i * 4 + 4]
                tempByte = strToBt(tempData)
                if firstKey != None and firstKey != "" and secondKey != None and secondKey != "" and thirdKey != None and thirdKey != "":
                    tempBt = tempByte
                    for x in range(0, firstLength):
                        tempBt = enc(tempBt, firstKeyBt[x])

                    for y in range(0, secondLength):
                        tempBt = enc(tempBt, secondKeyBt[y])

                    for z in range(0, thirdLength):
                        tempBt = enc(tempBt, thirdKeyBt[z])
                    encByte = tempBt
                elif firstKey != None and firstKey != "" and secondKey != None and secondKey != "":
                    tempBt = tempByte
                    for x in range(0, firstLength):
                        tempBt = enc(tempBt, firstKeyBt[x])

                    for y in range(0, secondLength):
                        tempBt = enc(tempBt, secondKeyBt[y])
                    encByte = tempBt
                elif firstKey != None and firstKey != "":
                    tempBt = tempByte
                    for x in range(0, firstLength):
                        tempBt = enc(tempBt, firstKeyBt[x])
                    encByte = tempBt

                encData += bt64ToHex(encByte)

        if remainder > 0:
            remainderData = data[iterator * 4 + 0:leng]
            tempByte = strToBt(remainderData)
            if firstKey != None and firstKey != "" and secondKey != None and secondKey != "" and thirdKey != None and thirdKey != "":
                tempBt = tempByte
                for x in range(0, firstLength):
                    tempBt = enc(tempBt, firstKeyBt[x])
                for y in range(0, secondLength):
                    tempBt = enc(tempBt, secondKeyBt[y])
                for z in range(0, thirdLength):
                    tempBt = enc(tempBt, thirdKeyBt[z])
                encByte = tempBt
            elif firstKey != None and firstKey != "" and secondKey != None and secondKey != "":
                tempBt = tempByte
                for x in range(0, firstLength):
                    tempBt = enc(tempBt, firstKeyBt[x])

                for y in range(0, secondLength):
                    tempBt = enc(tempBt, secondKeyBt[y])
                encByte = tempBt
            elif firstKey != None and firstKey != "":
                tempBt = tempByte
                for x in range(0, firstLength):
                    tempBt = enc(tempBt, firstKeyBt[x])
                encByte = tempBt
            encData += bt64ToHex(encByte)

    return encData