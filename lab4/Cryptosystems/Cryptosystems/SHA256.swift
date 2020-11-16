//
//  SHA256.swift
//  Cryptosystems
//
//  Created by Oleksii Andriushchenko on 16.11.2020.
//

import Foundation

final class SHA256 {

  private typealias Word = UInt32

  /// 64 bytes = 512 bits
  private let blockSize = 64
  private let wordSize = 4

  func hash(data: Data) -> Data {
    let paddedData = addPadding(to: data)
    let blockCount = paddedData.count / blockSize
    var hashVector: [Word] = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    for index in 0..<blockCount {
      let block = Data(paddedData[(index * blockSize)..<((index + 1) * blockSize)])
      let messageSchedule = prepareMessageSchedule(block: block)
      var (a, b, c, d, e, f, g, h) = (
        hashVector[0], hashVector[1], hashVector[2], hashVector[3],
        hashVector[4], hashVector[5], hashVector[6], hashVector[7]
      )
      for t in 0..<64 {
        let T1 = h &+ S1(e) &+ ch(e, f, g) &+ constantsK[t] &+ messageSchedule[t]
        let T2 = S0(a) &+ maj(a, b, c)
        h = g
        g = f
        f = e
        e = d &+ T1
        d = c
        c = b
        b = a
        a = T1 &+ T2
      }
      hashVector = [
        a &+ hashVector[0], b &+ hashVector[1], c &+ hashVector[2], d &+ hashVector[3],
        e &+ hashVector[4], f &+ hashVector[5], g &+ hashVector[6], h &+ hashVector[7],
      ]
    }

    return Data(hashVector.flatMap { getBytes(from: $0) })
  }

  private func addPadding(to data: Data) -> Data {
    var result = data
    result.append(contentsOf: [0b10000000])

    let size = result.count
    let zeroBytesCount = (64 + 56 - (size % 64)) % 64
    result.append(contentsOf: Array(repeating: UInt8.zero, count: zeroBytesCount))
    result.append(contentsOf: getBytes(from: data.count * 8))
    return result
  }

  private func prepareMessageSchedule(block: Data) -> [Word] {
    var bytes = [Word]()
    for index in 0..<64 {
      if index < 16 {
        let word = getWord(from: block, index: index)
        bytes.append(word)
      } else {
        let byte = s1(bytes[index - 2]) &+ bytes[index - 7] &+ s0(bytes[index - 15]) &+ bytes[index - 16]
        bytes.append(byte)
      }
    }
    return bytes
  }

  // Utilities

  private func getWord(from data: Data, index: Int) -> Word {
    var word = Word.zero
    for byteIndex in 0..<wordSize {
      word += Word(data[wordSize * index + byteIndex]) << (8 * (wordSize - byteIndex - 1))
    }
    return word
  }

  private func getBytes(from word: Word) -> [UInt8] {
    var result: [UInt8] = []
    for index in 0..<wordSize {
      let shiftedWord = word >> (8 * (wordSize - index - 1))
      let byte = UInt8(shiftedWord & 0xff)
      result.append(byte)
    }
    return result
  }

  private func getBytes(from number: Int) -> [UInt8] {
    var result: [UInt8] = []
    for index in 0..<8 {
      let shiftedWord = number >> (8 * (7 - index))
      let byte = UInt8(shiftedWord & 0xff)
      result.append(byte)
    }
    return result
  }

  private func ch(_ x: Word, _ y: Word, _ z: Word) -> Word {
    return (x & y) ^ (~x & z)
  }

  private func maj(_ x: Word, _ y: Word, _ z: Word) -> Word {
    return (x & y) ^ (x & z) ^ (y & z)
  }

  private func S0(_ word: Word) -> Word {
    return rotr(word, count: 2) ^ rotr(word, count: 13) ^ rotr(word, count: 22)
  }

  private func S1(_ word: Word) -> Word {
    return rotr(word, count: 6) ^ rotr(word, count: 11) ^ rotr(word, count: 25)
  }

  private func s0(_ word: Word) -> Word {
    return rotr(word, count: 7) ^ rotr(word, count: 18) ^ shr(word, count: 3)
  }

  private func s1(_ word: Word) -> Word {
    return rotr(word, count: 17) ^ rotr(word, count: 19) ^ shr(word, count: 10)
  }

  private func rotr(_ word: Word, count: Int) -> Word {
    return (word >> count) | (word << ((8 * wordSize) - count))
  }

  private func shr(_ word: Word, count: Int) -> Word {
    return word >> count
  }

  private let constantsK: [Word] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]
}
