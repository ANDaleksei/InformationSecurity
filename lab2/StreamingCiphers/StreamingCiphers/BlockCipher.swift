//
//  BlockCipher.swift
//  StreamingCiphers
//
//  Created by Oleksii Andriushchenko on 18.10.2020.
//

import Foundation

final class BlockCipher {
  enum Mode {
    case ecb
    case cbc
    case cfb(padding: Int)
    case ofb
    case ctr
  }

  private let aes: AesAlgorithm
  private let mode: Mode
  private let blockSize = 16

  init(key: Data, mode: Mode) {
    self.aes = AesAlgorithm(key: key)
    self.mode = mode
  }

  func encode(data: Data) -> Data {
    switch mode {
    case .ecb:
      return encodeECB(data: data)
    case .cbc:
      return encodeCBC(data: data)
    case .cfb(let padding):
      return encodeCFB(data: data, padding: padding)
    case .ofb:
      return encodeOFB(data: data)
    case .ctr:
      return encodeCTR(data: data)
    }
  }

  func decode(data: Data) -> Data {
    switch mode {
    case .ecb:
      return decodeECB(data: data)
    case .cbc:
      return decodeCBC(data: data)
    case .cfb(let padding):
      return decodeCFB(data: data, padding: padding)
    case .ofb:
      return decodeOFB(data: data)
    case .ctr:
      return decodeCTR(data: data)
    }
  }

  // Encode modes

  private func encodeECB(data: Data) -> Data {
    let count = data.count
    var result = Data()
    for index in 0..<(count / blockSize) {
      let block = Data(data[(index * blockSize)..<((index + 1) * blockSize)])
      result.append(aes.encodeBlock(data: block))
    }
    return Data(result)
  }

  private func encodeCBC(data: Data) -> Data {
    let count = data.count
    var result = Data()
    var prevBlock = Data(initVector)
    for index in 0..<(count / blockSize) {
      let dataBlock = Data(data[(index * blockSize)..<((index + 1) * blockSize)])
      let block = Data(xor(lhs: prevBlock.map { $0 }, rhs: dataBlock.map { $0 }))
      let resBlock = aes.encodeBlock(data: block)
      prevBlock = resBlock
      result.append(resBlock)
    }
    return Data(result)
  }

  private func encodeCFB(data: Data, padding: Int) -> Data {
    let count = data.count
    var result = Data()
    var prevBlock = Data(initVector)
    for index in 0..<(count / padding) {
      let outputBlock = aes.encodeBlock(data: prevBlock)
      let dataBlock = Data(data[(index * padding)..<((index + 1) * padding)])
      let partOutputBlock = Data(outputBlock.prefix(padding))
      let resBlock = Data(xor(lhs: dataBlock.map { $0 }, rhs: partOutputBlock.map { $0 }))
      result.append(resBlock)
      prevBlock = Data(prevBlock.suffix(blockSize - padding)) + resBlock
    }
    return Data(result)
  }

  private func encodeOFB(data: Data) -> Data {
    let count = data.count
    var result = Data()
    var prevBlock = Data(initVector)
    for index in 0..<(count / blockSize) {
      let outputBlock = aes.decodeBlock(data: prevBlock)
      prevBlock = outputBlock
      let block = Data(data[(index * blockSize)..<((index + 1) * blockSize)])
      result.append(Data(xor(lhs: outputBlock.map { $0 }, rhs: block.map { $0 })))
    }
    return Data(result)
  }

  private func encodeCTR(data: Data) -> Data {
    let count = data.count
    var result = Data()
    var vector = timeVector
    for index in 0..<(count / blockSize) {
      let outputBlock = aes.decodeBlock(data: Data(vector))
      increment(vector: &vector)
      let block = Data(data[(index * blockSize)..<((index + 1) * blockSize)])
      result.append(Data(xor(lhs: outputBlock.map { $0 }, rhs: block.map { $0 })))
    }
    return Data(result)
  }

  // Decode modes

  private func decodeECB(data: Data) -> Data {
    let count = data.count
    var result = Data()
    for index in 0..<(count / blockSize) {
      let block = Data(data[(index * blockSize)..<((index + 1) * blockSize)])
      result.append(aes.decodeBlock(data: block))
    }
    return Data(result)
  }

  private func decodeCBC(data: Data) -> Data {
    let count = data.count
    var result = Data()
    var prevBlock = Data(initVector)
    for index in 0..<(count / blockSize) {
      let dataBlock = Data(data[(index * blockSize)..<((index + 1) * blockSize)])
      let block = aes.decodeBlock(data: dataBlock)
      let resBlock = Data(xor(lhs: prevBlock.map { $0 }, rhs: block.map { $0 }))
      prevBlock = resBlock
      result.append(resBlock)
    }
    return Data(result)
  }

  private func decodeCFB(data: Data, padding: Int) -> Data {
    let count = data.count
    var result = Data()
    var prevBlock = Data(initVector)
    for index in 0..<(count / padding) {
      let outputBlock = aes.encodeBlock(data: prevBlock)
      let dataBlock = Data(data[(index * padding)..<((index + 1) * padding)])
      let partOutputBlock = Data(outputBlock.prefix(padding))
      let resBlock = Data(xor(lhs: dataBlock.map { $0 }, rhs: partOutputBlock.map { $0 }))
      result.append(resBlock)
      prevBlock = Data(prevBlock.suffix(blockSize - padding)) + dataBlock
    }
    return Data(result)
  }

  private func decodeOFB(data: Data) -> Data {
    let count = data.count
    var result = Data()
    var prevBlock = Data(initVector)
    for index in 0..<(count / blockSize) {
      let outputBlock = aes.decodeBlock(data: prevBlock)
      prevBlock = outputBlock
      let block = Data(data[(index * blockSize)..<((index + 1) * blockSize)])
      result.append(Data(xor(lhs: outputBlock.map { $0 }, rhs: block.map { $0 })))
    }
    return Data(result)
  }

  private func decodeCTR(data: Data) -> Data {
    let count = data.count
    var result = Data()
    var vector = timeVector
    for index in 0..<(count / blockSize) {
      let outputBlock = aes.decodeBlock(data: Data(vector))
      increment(vector: &vector)
      let block = Data(data[(index * blockSize)..<((index + 1) * blockSize)])
      result.append(Data(xor(lhs: outputBlock.map { $0 }, rhs: block.map { $0 })))
    }
    return Data(result)
  }
}
