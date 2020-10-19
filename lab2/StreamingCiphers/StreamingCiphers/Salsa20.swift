//
//  Salsa20.swift
//  StreamingCiphers
//
//  Created by Oleksii Andriushchenko on 18.10.2020.
//

import Foundation

final class Salsa20 {

  private let key: [Word]

  init(key: Data) {
    let keyArray = key.map { $0 }
    self.key = [
      [keyArray[0], keyArray[1], keyArray[2], keyArray[3]],
      [keyArray[4], keyArray[5], keyArray[6], keyArray[7]],
      [keyArray[8], keyArray[9], keyArray[10], keyArray[11]],
      [keyArray[12], keyArray[13], keyArray[14], keyArray[15]]
    ]
  }

  func encode(data: Data) -> Data {
    return transform(data: data)
  }

  func decode(data: Data) -> Data {
    return transform(data: data)
  }

  private func transform(data: Data) -> Data {
    let count = data.count
    var result: [UInt8] = []
    for index in 0...(count / 64) {
      let table = generateTable(index: UInt64(index))
      for lowIndex in 0..<(min(count - index * 64, 64)) {
        result.append(data[index * 64 + lowIndex] ^ table[lowIndex / 4][lowIndex % 4])
      }
    }
    return Data(result)
  }

  private func generateTable(index: UInt64) -> [Word] {
    return [
      [0x67, 0x70, 0x78, 0x65], key[0], key[1], key[2],
      key[3], [0x33, 0x20, 0x64, 0x6e], [0x01, 0x04, 0x01, 0x03], [0x06, 0x02, 0x09, 0x05],
      leftPosWord(index: index), rightPosWord(index: index), [0x79, 0x62, 0x2d, 0x32], key[0],
      key[1], key[2], key[3], [0x6b, 0x20, 0x65, 0x74]
    ]
  }

  private func leftPosWord(index: UInt64) -> Word {
    let value32 = UInt32(index >> 32)
    return [
      UInt8(value32 >> 24),
      UInt8((value32 >> 16) & 0xff),
      UInt8((value32 >> 8) & 0xff),
      UInt8(value32 & 0xff)
    ]
  }

  private func rightPosWord(index: UInt64) -> Word {
    let value32 = UInt32(index & 0xffffffff)
    return [
      UInt8(value32 >> 24),
      UInt8((value32 >> 16) & 0xff),
      UInt8((value32 >> 8) & 0xff),
      UInt8(value32 & 0xff)
    ]
  }

  private func transform(words: [Word]) -> [Word] {
    return xor(lhs: words, rhs: applyDoubleRound(words: words, count: 10))
  }

  private func quarterRound(words: [Word]) -> [Word] {
    let z1 = xor(lhs: words[1], rhs: add(lhs: words[0], rhs: words[3]).shiftedLeft(by: 7))
    let z2 = xor(lhs: words[2], rhs: add(lhs: z1, rhs: words[0]).shiftedLeft(by: 9))
    let z3 = xor(lhs: words[3], rhs: add(lhs: z2, rhs: z1).shiftedLeft(by: 13))
    let z0 = xor(lhs: words[0], rhs: add(lhs: z3, rhs: z2).shiftedLeft(by: 18))
    return [z0, z1, z2, z3]
  }

  private func rowRound(words: [Word]) -> [Word] {
    return quarterRound(words: [words[0], words[1], words[2], words[3]])
      + quarterRound(words: [words[5], words[6], words[7], words[4]])
      + quarterRound(words: [words[10], words[11], words[8], words[9]])
      + quarterRound(words: [words[15], words[12], words[13], words[14]])
  }

  private func columnRound(words: [Word]) -> [Word] {
    return quarterRound(words: [words[0], words[4], words[8], words[12]])
      + quarterRound(words: [words[5], words[9], words[13], words[1]])
      + quarterRound(words: [words[10], words[14], words[2], words[6]])
      + quarterRound(words: [words[15], words[3], words[7], words[11]])
  }

  private func doubleRound(words: [Word]) -> [Word] {
    return rowRound(words: columnRound(words: words))
  }

  private func applyDoubleRound(words: [Word], count: Int) -> [Word] {
    var result = words
    for _ in 0..<count {
      result = doubleRound(words: result)
    }
    return result
  }
}
