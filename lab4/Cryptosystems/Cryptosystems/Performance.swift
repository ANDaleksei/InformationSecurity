//
//  Performance.swift
//  Cryptosystems
//
//  Created by Oleksii Andriushchenko on 16.11.2020.
//

import Foundation

func checkPerformance() {
  let bits = [256, 384, 512, 640, 768, 896, 1024]
  let data = "Example text".data(using: .utf8)!
  for numberOfBits in bits {
    print("New iteration, number of bits = \(numberOfBits)")
    let rsa = RSA(bitCount: numberOfBits)

    print("RSA, Start encrypting.")
    var startTime = CFAbsoluteTimeGetCurrent()
    let encryptedDataRSA = rsa.encrypt(data: data)
    var timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
    print("RSA, End encrypting, time taken in seconds: \(timeElapsed)")

    print("RSA, Start decrypting.")
    startTime = CFAbsoluteTimeGetCurrent()
    _ = rsa.decrypt(data: encryptedDataRSA)
    timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
    print("RSA, End decrypting, time taken in seconds: \(timeElapsed)")

    let rsaOAEP = RSAOAEP(bitCount: numberOfBits)
    print("RSA OAEP, Start encrypting.")
    startTime = CFAbsoluteTimeGetCurrent()
    let encryptedDataRSAOAEP = rsaOAEP.encrypt(data: data)
    timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
    print("RSA OAEP, End encrypting, time taken in seconds: \(timeElapsed)")

    print("RSA OAEP, Start decrypting.")
    startTime = CFAbsoluteTimeGetCurrent()
    _ = rsaOAEP.decrypt(data: encryptedDataRSAOAEP)
    timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
    print("RSA OAEP, End decrypting, time taken in seconds: \(timeElapsed)")
  }
}
