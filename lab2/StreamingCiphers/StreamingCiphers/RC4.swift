//
//  RC4.swift
//  StreamingCiphers
//
//  Created by Oleksii Andriushchenko on 18.10.2020.
//

import Foundation

final class RC4 {

  private let sTable: [Int]

  init(key: Data) {
    self.sTable = generateSTable(key: key.map { $0 })
  }

  func encode(data: Data) -> Data {
    return transform(data: data)
  }

  func decode(data: Data) -> Data {
    return transform(data: data)
  }

  private func transform(data: Data) -> Data {
    var i = 0
    var j = 0
    var sCopy = sTable

    func generateWord() -> UInt8 {
      i = (i + 1) % 256
      j = (j + sCopy[i]) % 256
      sCopy.swapAt(i, j)
      let t = (sCopy[i] + sCopy[j]) % 256
      return UInt8(sCopy[t])
    }

    var result = data
    for index in 0..<data.count {
      result[index] ^= generateWord()
    }

    return result
  }
}

private func generateSTable(key: [UInt8]) -> [Int] {
  var sTable = Array(0..<256)
  var j = 0
  let keyCount = key.count
  for index in 0...255 {
    j = (j + sTable[index] + Int(key[index % keyCount])) % 256
    sTable.swapAt(index, j)
  }
  return sTable
}
