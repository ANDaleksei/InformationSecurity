//
//  RSAOAEP.swift
//  Cryptosystems
//
//  Created by Oleksii Andriushchenko on 16.11.2020.
//

import Foundation

final class RSAOAEP {

  private let rsa: RSA
  private let sha: SHA256
  private let r: Data = Data((0..<32).map { _ in UInt8.random(in: 0...UInt8.max) })

  init(bitCount: Int) {
    self.rsa = RSA(bitCount: bitCount)
    self.sha = SHA256()
  }

  func encrypt(data: Data) -> Data {
    assert(data.count * 8 < rsa.nBitsCount - 256)
    let k1 = Data([UInt8.zero])
    let combinedData = data + k1
    let gRes = g(r, targetLength: data.count + 1)
    let x = xor(lhs: combinedData, rhs: gRes)
    let hRes = h(x)
    let y = xor(lhs: hRes, rhs: r)
    let inputData = x + y
    return rsa.encrypt(data: inputData)
  }

  func decrypt(data: Data) -> Data {
    let rsaOutput = rsa.decrypt(data: data)
    let x = Data(rsaOutput[0..<(rsaOutput.count - 32)])
    let y = Data(rsaOutput[(rsaOutput.count - 32)..<rsaOutput.count])
    let hRes = h(x)
    let rExp = xor(lhs: hRes, rhs: y)
    assert(rExp == r)
    let gRes = g(r, targetLength: x.count)
    let combinedData = xor(lhs: x, rhs: gRes)
    let m = Data(combinedData[0..<(combinedData.count - 1)])
    let zeros = Data(combinedData[(combinedData.count - 1)..<combinedData.count])
    assert(zeros == Data([UInt8.zero]))
    return m
  }

  private func g(_ data: Data, targetLength: Int) -> Data {
    var output = Data()
    var counter = 0
    while output.count < targetLength {
      let counterData = getData(from: counter)
      output.append(sha.hash(data: data + counterData))
      counter += 1
    }
    return Data(output[0..<targetLength])
  }

  private func h(_ data: Data) -> Data {
    return sha.hash(data: data)
  }

  private func xor(lhs: Data, rhs: Data) -> Data {
    return Data(zip(lhs.map { $0 }, rhs.map { $0 }).map { $0 ^ $1 })
  }

  private func getData(from number: Int) -> Data {
    let value = number & 0xffff
    return Data([UInt8((value >> 8) & 0xff), UInt8(value & 0xff)])
  }
}
