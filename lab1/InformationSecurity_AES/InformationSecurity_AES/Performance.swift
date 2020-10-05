//
//  Performance.swift
//  InformationSecurity_AES
//
//  Created by Oleksii Andriushchenko on 05.10.2020.
//

import Foundation

func checkPerformance() {
  let text: String = Array(0..<100000).map { _ in String("abcdefghijcklmnopqrstuvwzyx".randomElement()!) }.joined()

  let aes = AesAlgorithm(key: Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]))
  let kalyna = KalynaAlgorithm(key: Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]))

  var startTime = CFAbsoluteTimeGetCurrent()
  let encryptedDataAES = aes.encrypt(text: text)
  var timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("AES, encrypt 1 MB in seconds: \(timeElapsed)")

  startTime = CFAbsoluteTimeGetCurrent()
  let _: Data = aes.decrypt(data: encryptedDataAES)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("AES, decrypt 1 MB in seconds: \(timeElapsed)")

  startTime = CFAbsoluteTimeGetCurrent()
  let encryptedDataKalyna = kalyna.encrypt(text: text)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("Kalyna, encrypt 1 MB in seconds: \(timeElapsed)")

  startTime = CFAbsoluteTimeGetCurrent()
  let _: Data = kalyna.decrypt(data: encryptedDataKalyna)
  timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
  print("Kalyna, decrypt 1 MB in seconds: \(timeElapsed)")
}
