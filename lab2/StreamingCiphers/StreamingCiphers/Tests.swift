//
//  Tests.swift
//  StreamingCiphers
//
//  Created by Oleksii Andriushchenko on 18.10.2020.
//

import Foundation

func testRC4() {
  // secret_key
  let key: [UInt8] = [115, 101, 99, 114, 101, 116, 95, 107, 101, 121]
  // secret_text
  let text: [UInt8] = [115, 101, 99, 114, 101, 116, 95, 116, 101, 120, 116]
  let rc4 = RC4(key: Data(key))
  let encodedData = rc4.encode(data: Data(text))
  let decodedData = rc4.decode(data: encodedData)


  let expectedEncodedData = Data([48, 90, 248, 211, 165, 33, 180, 82, 44, 152, 192])
  assert(encodedData == expectedEncodedData)
  assert(decodedData == Data(text))
}

func testSalsa20() {
  // secret_key
  let key: [UInt8] = [
    0x04, 0x03, 0x03, 0x01,
    0x08, 0x07, 0x06, 0x05,
    0x0c, 0x0b, 0x0a, 0x09,
    0x10, 0x0f, 0x0e, 0x0d
  ]
  // secret_text
  let text: [UInt8] = [115, 101, 99, 114, 101, 116, 95, 116, 101, 120, 116]
  let salsa = Salsa20(key: Data(key))
  let encodedData = salsa.encode(data: Data(text))
  let decodedData = salsa.decode(data: encodedData)


  let expectedEncodedData = Data([20, 21, 27, 23, 97, 119, 92, 117, 109, 127, 114])
  assert(encodedData == expectedEncodedData)
  assert(decodedData == Data(text))
}

func testECB() {
  let key: [UInt8] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  ]
  // secret_text_word
  let text: [UInt8] = [
    115, 101, 99, 114, 101, 116, 95, 116,
    101, 120, 116, 95, 119, 111, 114, 100
  ]
  let ecbCipher = BlockCipher(key: Data(key), mode: .ecb)
  let encodedData = ecbCipher.encode(data: Data(text))
  let decodedData = ecbCipher.decode(data: encodedData)

  let expectedEncodedData = Data([109, 25, 111, 4, 129, 109, 94, 237, 139, 207, 2, 246, 148, 213, 10, 168])
  assert(encodedData == expectedEncodedData)
  assert(decodedData == Data(text))
}

func testCBC() {
  let key: [UInt8] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  ]
  // secret_text_word
  let text: [UInt8] = [
    115, 101, 99, 114, 101, 116, 95, 116,
    101, 120, 116, 95, 119, 111, 114, 100
  ]
  let cbcCipher = BlockCipher(key: Data(key), mode: .cbc)
  let encodedData = cbcCipher.encode(data: Data(text))
  let decodedData = cbcCipher.decode(data: encodedData)

  let expectedEncodedData = Data([197, 79, 227, 202, 166, 170, 10, 8, 92, 177, 227, 67, 41, 6, 150, 67])
  assert(encodedData == expectedEncodedData)
  assert(decodedData == Data(text))
}

func testCFB() {
  let key: [UInt8] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  ]
  // secret_texts
  let text: [UInt8] = [
    115, 101, 99, 114, 101, 116,
    95, 116, 101, 120, 116, 115
  ]
  let cfbCipher = BlockCipher(key: Data(key), mode: .cfb(padding: 6))
  let encodedData = cfbCipher.encode(data: Data(text))
  let decodedData = cfbCipher.decode(data: encodedData)

  let expectedEncodedData = Data([165, 91, 69, 147, 1, 165, 49, 183, 190, 109, 249, 53])
  assert(encodedData == expectedEncodedData)
  assert(decodedData == Data(text))
}

func testOFB() {
  // secret_key
  let key: [UInt8] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  ]
  // secret_text
  let text: [UInt8] = [
    115, 101, 99, 114, 101, 116, 95, 116,
    101, 120, 116, 116, 116, 116, 116, 116
  ]
  let ofbCipher = BlockCipher(key: Data(key), mode: .ofb)
  let encodedData = ofbCipher.encode(data: Data(text))
  let decodedData = ofbCipher.decode(data: encodedData)

  let expectedEncodedData = Data([14, 205, 10, 18, 111, 120, 104, 61, 218, 207, 183, 160, 93, 236, 224, 175])
  assert(encodedData == expectedEncodedData)
  assert(decodedData == Data(text))
}

func testCTR() {
  let key: [UInt8] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  ]
  // secret_text
  let text: [UInt8] = [
    115, 101, 99, 114, 101, 116, 95, 116,
    101, 120, 116, 116, 116, 116, 116, 116
  ]
  let ctrCipher = BlockCipher(key: Data(key), mode: .ctr)
  let encodedData = ctrCipher.encode(data: Data(text))
  let decodedData = ctrCipher.decode(data: encodedData)

  let expectedEncodedData = Data([14, 205, 10, 18, 111, 120, 104, 61, 218, 207, 183, 160, 93, 236, 224, 175])
  assert(encodedData == expectedEncodedData)
  assert(decodedData == Data(text))
}
