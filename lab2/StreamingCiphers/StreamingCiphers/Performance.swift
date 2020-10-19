//
//  Performance.swift
//  StreamingCiphers
//
//  Created by Oleksii Andriushchenko on 19.10.2020.
//

import Foundation

func testPerformance() {
  let text: String = Array(0..<10000000).map { _ in String("abcdefghijcklmnopqrstuvwzyx".randomElement()!) }.joined()
  let data = text.data(using: .utf8)!
  let key: Data = Data([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  ])

  let rc4 = RC4(key: key)
  let salsa = Salsa20(key: key)
  let ecbCipher = BlockCipher(key: key, mode: .ecb)
  let cbcCipher = BlockCipher(key: key, mode: .cbc)
  let cfbCipher = BlockCipher(key: key, mode: .cfb(padding: 10))
  let ofbCipher = BlockCipher(key: key, mode: .ofb)
  let ctrCipher = BlockCipher(key: key, mode: .ctr)

  // MARK: - RC4

  var startTime = CFAbsoluteTimeGetCurrent()
  let encryptedDataRC4 = rc4.encode(data: data)
  var timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("RC4, encode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")

  startTime = CFAbsoluteTimeGetCurrent()
  let _: Data = rc4.decode(data: encryptedDataRC4)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("RC4, decode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")

  // MARK: - Salsa20

  startTime = CFAbsoluteTimeGetCurrent()
  let encryptedDataSalsa = salsa.encode(data: data)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("Salsa20, encode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")

  startTime = CFAbsoluteTimeGetCurrent()
  let _: Data = salsa.decode(data: encryptedDataSalsa)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("Salsa20, decode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")

  // MARK: - ECB

  startTime = CFAbsoluteTimeGetCurrent()
  let encryptedDataECB = ecbCipher.encode(data: data)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("ECB mode, encode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")

  startTime = CFAbsoluteTimeGetCurrent()
  let _: Data = ecbCipher.decode(data: encryptedDataECB)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("ECB mode, decode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")

  // MARK: - CBC

  startTime = CFAbsoluteTimeGetCurrent()
  let encryptedDataCBC = cbcCipher.encode(data: data)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("CBC mode, encode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")

  startTime = CFAbsoluteTimeGetCurrent()
  let _: Data = cbcCipher.decode(data: encryptedDataCBC)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("CBC mode, decode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")

  // MARK: - CFB

  startTime = CFAbsoluteTimeGetCurrent()
  let encryptedDataCFB = cfbCipher.encode(data: data)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("CFB mode, encode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")

  startTime = CFAbsoluteTimeGetCurrent()
  let _: Data = cfbCipher.decode(data: encryptedDataCFB)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("CFB mode, decode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")

  // MARK: - OFB

  startTime = CFAbsoluteTimeGetCurrent()
  let encryptedDataOFB = ofbCipher.encode(data: data)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("OFB mode, encode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")

  startTime = CFAbsoluteTimeGetCurrent()
  let _: Data = ofbCipher.decode(data: encryptedDataOFB)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("OFB mode, decode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")

  // MARK: - CTR

  startTime = CFAbsoluteTimeGetCurrent()
  let encryptedDataCTR = ctrCipher.encode(data: data)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("CTR mode, encode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")

  startTime = CFAbsoluteTimeGetCurrent()
  let _: Data = ctrCipher.decode(data: encryptedDataCTR)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("CTR mode, decode \(Double(text.count) / 1000000) MB in seconds: \(timeElapsed)")
}
