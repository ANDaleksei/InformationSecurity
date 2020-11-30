//
//  Kupyna.swift
//  EllipticCurve
//
//  Created by Oleksii Andriushchenko on 30.11.2020.
//

import Foundation

final class Kupyna {

  // 1...64
  private let s: Int
  // 8 * s
  private let n: Int
  // 512, 1024
  private let l: Int
  private let k: Int

  init(s: Int) {
    self.s = s
    self.n = 8 * s
    self.l = 256 < 8 * s ? 1024 : 512
    self.k = 256 < 8 * s ? 14 : 10

    setupMultiplyTable()
  }

  func hash(data: Data) -> Data {
    var vector = getIV()
    let paddedData = addPadding(to: data)
    let blockSize = l / 8
    let blockCount = paddedData.count / blockSize
    for index in 0..<blockCount {
      let block = Data(paddedData[(index * blockSize)..<((index + 1) * blockSize)]).map { $0 }
      vector = xor(mappingTXor(bytes: xor(lhs: vector, rhs: block)), mappingTPlus(bytes: block), vector)
    }
    let final = xor(lhs: mappingTXor(bytes: vector), rhs: vector)
    let hash = Data(slice(bytes: final))
    return hash
  }

  private func addPadding(to data: Data) -> Data {
    var result = data
    result.append(contentsOf: [0b10000000])

    let size = result.count
    let blockSize = l / 8
    let zeroBytesCount = (blockSize - 12 - (size % blockSize)) % blockSize
    result.append(contentsOf: Array(repeating: UInt8.zero, count: zeroBytesCount))
    result.append(contentsOf: getBytes(from: data.count * 8))
    return result
  }

  private func getBytes(from number: Int) -> [UInt8] {
    var result: [UInt8] = []
    for index in 0..<12 {
      let shiftedWord = number >> (8 * (12 - index - 1))
      let byte = UInt8(shiftedWord & 0xff)
      result.append(byte)
    }
    return result.reversed()
  }

  private func getIV() -> [UInt8] {
    if l == 512 {
      return [1 << 6] + Array(repeating: 0, count: l / 8 - 1)
    } else {
      return [1 << 7] + Array(repeating: 0, count: l / 8 - 1)
    }
  }

  private func mappingTXor(bytes: [UInt8]) -> [UInt8] {
    var state = makeState(bytes: bytes)
    for round in 0..<k {
      addModulo2(state: &state, round: round)
      subBytes(state: &state)
      shiftRows(state: &state)
      linearTransformation(state: &state)
    }
    return state.flatMap { $0 }
  }

  private func mappingTPlus(bytes: [UInt8]) -> [UInt8] {
    var state = makeState(bytes: bytes)
    for round in 0..<k {
      addModulo2in64(state: &state, round: round)
      subBytes(state: &state)
      shiftRows(state: &state)
      linearTransformation(state: &state)
    }
    return state.flatMap { $0 }
  }

  private func makeState(bytes: [UInt8]) -> [[UInt8]] {
    stride(from: 0, to: bytes.count, by: 8).map { Array(bytes[$0..<($0 + 8)]) }
  }

  private func addModulo2in64(state: inout [[UInt8]], round: Int) {
    let rowsCount = state.count
    for (index, row) in state.enumerated() {
      // missed in pdf
      let vector: [UInt8] = [0xf3, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, (UInt8(rowsCount - 1 - index) << 4) + UInt8(round)]
      state[index] = add(lhs: row, rhs: vector)
    }
  }

  private func add(lhs: [UInt8], rhs: [UInt8]) -> [UInt8] {
    var result: [UInt8] = []
    var isOverflow = false
    zip(lhs, rhs).forEach { left, right in
      let (value, overflow) = left.addingReportingOverflow(right)
      let (value1, overflow1) = value.addingReportingOverflow(isOverflow ? 1 : 0)
      result.append(value1)
      isOverflow = overflow || overflow1
    }
    return result
  }

  private func addModulo2(state: inout [[UInt8]], round: Int) {
    for row in 0..<state.count {
      let vector: [UInt8] = [(UInt8(row) << 4) ^ UInt8(round), 0, 0, 0, 0, 0, 0, 0]
      for column in 0..<state[0].count {
        state[row][column] ^= vector[column]
      }
    }
  }

  private func subBytes(state: inout [[UInt8]]) {
    for row in 0..<state.count {
      for column in 0..<state[row].count {
        state[row][column] = kalynaBoxes[column % 4][Int(state[row][column])]
      }
    }
  }

  private func shiftRows(state: inout [[UInt8]]) {
    let copy = state
    for columnIndex in 0..<8 {
      let shift: Int
      if columnIndex == 7 {
        shift = l == 512 ? 7 : 11
      } else {
        shift = columnIndex
      }
      for row in 0..<state.count {
        state[row][columnIndex] = copy[(state.count + row - shift) % state.count][columnIndex]
      }
    }
  }

  private let vectors: [[UInt8]] = [
    [1, 1, 5, 1, 8, 6, 7, 4],
    [4, 1, 1, 5, 1, 8, 6, 7],
    [7, 4, 1, 1, 5, 1, 8, 6],
    [6, 7, 4, 1, 1, 5, 1, 8],
    [8, 6, 7, 4, 1, 1, 5, 1],
    [1, 8, 6, 7, 4, 1, 1, 5],
    [5, 1, 8, 6, 7, 4, 1, 1],
    [1, 5, 1, 8, 6, 7, 4, 1]
  ]

  private func linearTransformation(state: inout [[UInt8]]) {
    let copy = state
    for column in 0..<8 {
      for row in 0..<copy.count {
        state[row][column] = scalarProdcut(lhs: vectors[column], rhs: copy[row])
      }
    }
  }

  private func scalarProdcut(lhs: [UInt8], rhs: [UInt8]) -> UInt8 {
    return multiplyTable[Int(lhs[0])][Int(rhs[0])]
      ^ multiplyTable[Int(lhs[1])][Int(rhs[1])]
      ^ multiplyTable[Int(lhs[2])][Int(rhs[2])]
      ^ multiplyTable[Int(lhs[3])][Int(rhs[3])]
      ^ multiplyTable[Int(lhs[4])][Int(rhs[4])]
      ^ multiplyTable[Int(lhs[5])][Int(rhs[5])]
      ^ multiplyTable[Int(lhs[6])][Int(rhs[6])]
      ^ multiplyTable[Int(lhs[7])][Int(rhs[7])]
  }

  private func xor(lhs: [UInt8], rhs: [UInt8]) -> [UInt8] {
    return zip(lhs, rhs).map { $0 ^ $1 }
  }

  private func xor(_ a: [UInt8], _ b: [UInt8], _ c: [UInt8]) -> [UInt8] {
    zip(zip(a, b).map { $0 ^ $1}, c).map { $0 ^ $1}
  }

  private func slice(bytes: [UInt8]) -> [UInt8] {
    return bytes.suffix(s)
  }

  // Utilities

  private var multiplyTable: [[UInt8]] = .init(repeatElement([UInt8](repeating: 0, count: 256), count: 256))
  private func setupMultiplyTable() {
    for row in 0..<256 {
      for column in 0..<256 {
        multiplyTable[row][column] = multiply(lhs: UInt8(row), rhs: UInt8(column))
      }
    }
  }

  private func multiply(lhs: UInt8, rhs: UInt8) -> UInt8 {
    var result: UInt8 = 0
    var left = UInt8(lhs)
    var right = UInt8(rhs)
    while left > 0 && right > 0 {
      if right & 1 != 0 {
        result ^= left
      }

      if left & 0x80 != 0 {
        left = (left << 1) ^ 0x1d
      } else {
        left <<= 1
      }
      right >>= 1
    }
    return UInt8(result)
  }
}

let kalynaBoxes: [[UInt8]] = [pi0Box, pi1Box, pi2Box, pi3Box]

let pi0Box: [UInt8] = [
  0xA8, 0x43, 0x5F, 0x06, 0x6B, 0x75, 0x6C, 0x59, 0x71, 0xDF, 0x87, 0x95, 0x17, 0xF0, 0xD8, 0x09,
  0x6D, 0xF3, 0x1D, 0xCB, 0xC9, 0x4D, 0x2C, 0xAF, 0x79, 0xE0, 0x97, 0xFD, 0x6F, 0x4B, 0x45, 0x39,
  0x3E, 0xDD, 0xA3, 0x4F, 0xB4, 0xB6, 0x9A, 0x0E, 0x1F, 0xBF, 0x15, 0xE1, 0x49, 0xD2, 0x93, 0xC6,
  0x92, 0x72, 0x9E, 0x61, 0xD1, 0x63, 0xFA, 0xEE, 0xF4, 0x19, 0xD5, 0xAD, 0x58, 0xA4, 0xBB, 0xA1,
  0xDC, 0xF2, 0x83, 0x37, 0x42, 0xE4, 0x7A, 0x32, 0x9C, 0xCC, 0xAB, 0x4A, 0x8F, 0x6E, 0x04, 0x27,
  0x2E, 0xE7, 0xE2, 0x5A, 0x96, 0x16, 0x23, 0x2B, 0xC2, 0x65, 0x66, 0x0F, 0xBC, 0xA9, 0x47, 0x41,
  0x34, 0x48, 0xFC, 0xB7, 0x6A, 0x88, 0xA5, 0x53, 0x86, 0xF9, 0x5B, 0xDB, 0x38, 0x7B, 0xC3, 0x1E,
  0x22, 0x33, 0x24, 0x28, 0x36, 0xC7, 0xB2, 0x3B, 0x8E, 0x77, 0xBA, 0xF5, 0x14, 0x9F, 0x08, 0x55,
  0x9B, 0x4C, 0xFE, 0x60, 0x5C, 0xDA, 0x18, 0x46, 0xCD, 0x7D, 0x21, 0xB0, 0x3F, 0x1B, 0x89, 0xFF,
  0xEB, 0x84, 0x69, 0x3A, 0x9D, 0xD7, 0xD3, 0x70, 0x67, 0x40, 0xB5, 0xDE, 0x5D, 0x30, 0x91, 0xB1,
  0x78, 0x11, 0x01, 0xE5, 0x00, 0x68, 0x98, 0xA0, 0xC5, 0x02, 0xA6, 0x74, 0x2D, 0x0B, 0xA2, 0x76,
  0xB3, 0xBE, 0xCE, 0xBD, 0xAE, 0xE9, 0x8A, 0x31, 0x1C, 0xEC, 0xF1, 0x99, 0x94, 0xAA, 0xF6, 0x26,
  0x2F, 0xEF, 0xE8, 0x8C, 0x35, 0x03, 0xD4, 0x7F, 0xFB, 0x05, 0xC1, 0x5E, 0x90, 0x20, 0x3D, 0x82,
  0xF7, 0xEA, 0x0A, 0x0D, 0x7E, 0xF8, 0x50, 0x1A, 0xC4, 0x07, 0x57, 0xB8, 0x3C, 0x62, 0xE3, 0xC8,
  0xAC, 0x52, 0x64, 0x10, 0xD0, 0xD9, 0x13, 0x0C, 0x12, 0x29, 0x51, 0xB9, 0xCF, 0xD6, 0x73, 0x8D,
  0x81, 0x54, 0xC0, 0xED, 0x4E, 0x44, 0xA7, 0x2A, 0x85, 0x25, 0xE6, 0xCA, 0x7C, 0x8B, 0x56, 0x80
]

let pi1Box: [UInt8] = [
  0xCE, 0xBB, 0xEB, 0x92, 0xEA, 0xCB, 0x13, 0xC1, 0xE9, 0x3A, 0xD6, 0xB2, 0xD2, 0x90, 0x17, 0xF8,
  0x42, 0x15, 0x56, 0xB4, 0x65, 0x1C, 0x88, 0x43, 0xC5, 0x5C, 0x36, 0xBA, 0xF5, 0x57, 0x67, 0x8D,
  0x31, 0xF6, 0x64, 0x58, 0x9E, 0xF4, 0x22, 0xAA, 0x75, 0x0F, 0x02, 0xB1, 0xDF, 0x6D, 0x73, 0x4D,
  0x7C, 0x26, 0x2E, 0xF7, 0x08, 0x5D, 0x44, 0x3E, 0x9F, 0x14, 0xC8, 0xAE, 0x54, 0x10, 0xD8, 0xBC,
  0x1A, 0x6B, 0x69, 0xF3, 0xBD, 0x33, 0xAB, 0xFA, 0xD1, 0x9B, 0x68, 0x4E, 0x16, 0x95, 0x91, 0xEE,
  0x4C, 0x63, 0x8E, 0x5B, 0xCC, 0x3C, 0x19, 0xA1, 0x81, 0x49, 0x7B, 0xD9, 0x6F, 0x37, 0x60, 0xCA,
  0xE7, 0x2B, 0x48, 0xFD, 0x96, 0x45, 0xFC, 0x41, 0x12, 0x0D, 0x79, 0xE5, 0x89, 0x8C, 0xE3, 0x20,
  0x30, 0xDC, 0xB7, 0x6C, 0x4A, 0xB5, 0x3F, 0x97, 0xD4, 0x62, 0x2D, 0x06, 0xA4, 0xA5, 0x83, 0x5F,
  0x2A, 0xDA, 0xC9, 0x00, 0x7E, 0xA2, 0x55, 0xBF, 0x11, 0xD5, 0x9C, 0xCF, 0x0E, 0x0A, 0x3D, 0x51,
  0x7D, 0x93, 0x1B, 0xFE, 0xC4, 0x47, 0x09, 0x86, 0x0B, 0x8F, 0x9D, 0x6A, 0x07, 0xB9, 0xB0, 0x98,
  0x18, 0x32, 0x71, 0x4B, 0xEF, 0x3B, 0x70, 0xA0, 0xE4, 0x40, 0xFF, 0xC3, 0xA9, 0xE6, 0x78, 0xF9,
  0x8B, 0x46, 0x80, 0x1E, 0x38, 0xE1, 0xB8, 0xA8, 0xE0, 0x0C, 0x23, 0x76, 0x1D, 0x25, 0x24, 0x05,
  0xF1, 0x6E, 0x94, 0x28, 0x9A, 0x84, 0xE8, 0xA3, 0x4F, 0x77, 0xD3, 0x85, 0xE2, 0x52, 0xF2, 0x82,
  0x50, 0x7A, 0x2F, 0x74, 0x53, 0xB3, 0x61, 0xAF, 0x39, 0x35, 0xDE, 0xCD, 0x1F, 0x99, 0xAC, 0xAD,
  0x72, 0x2C, 0xDD, 0xD0, 0x87, 0xBE, 0x5E, 0xA6, 0xEC, 0x04, 0xC6, 0x03, 0x34, 0xFB, 0xDB, 0x59,
  0xB6, 0xC2, 0x01, 0xF0, 0x5A, 0xED, 0xA7, 0x66, 0x21, 0x7F, 0x8A, 0x27, 0xC7, 0xC0, 0x29, 0xD7
]

let pi2Box: [UInt8] = [
  0x93, 0xD9, 0x9A, 0xB5, 0x98, 0x22, 0x45, 0xFC, 0xBA, 0x6A, 0xDF, 0x02, 0x9F, 0xDC, 0x51, 0x59,
  0x4A, 0x17, 0x2B, 0xC2, 0x94, 0xF4, 0xBB, 0xA3, 0x62, 0xE4, 0x71, 0xD4, 0xCD, 0x70, 0x16, 0xE1,
  0x49, 0x3C, 0xC0, 0xD8, 0x5C, 0x9B, 0xAD, 0x85, 0x53, 0xA1, 0x7A, 0xC8, 0x2D, 0xE0, 0xD1, 0x72,
  0xA6, 0x2C, 0xC4, 0xE3, 0x76, 0x78, 0xB7, 0xB4, 0x09, 0x3B, 0x0E, 0x41, 0x4C, 0xDE, 0xB2, 0x90,
  0x25, 0xA5, 0xD7, 0x03, 0x11, 0x00, 0xC3, 0x2E, 0x92, 0xEF, 0x4E, 0x12, 0x9D, 0x7D, 0xCB, 0x35,
  0x10, 0xD5, 0x4F, 0x9E, 0x4D, 0xA9, 0x55, 0xC6, 0xD0, 0x7B, 0x18, 0x97, 0xD3, 0x36, 0xE6, 0x48,
  0x56, 0x81, 0x8F, 0x77, 0xCC, 0x9C, 0xB9, 0xE2, 0xAC, 0xB8, 0x2F, 0x15, 0xA4, 0x7C, 0xDA, 0x38,
  0x1E, 0x0B, 0x05, 0xD6, 0x14, 0x6E, 0x6C, 0x7E, 0x66, 0xFD, 0xB1, 0xE5, 0x60, 0xAF, 0x5E, 0x33,
  0x87, 0xC9, 0xF0, 0x5D, 0x6D, 0x3F, 0x88, 0x8D, 0xC7, 0xF7, 0x1D, 0xE9, 0xEC, 0xED, 0x80, 0x29,
  0x27, 0xCF, 0x99, 0xA8, 0x50, 0x0F, 0x37, 0x24, 0x28, 0x30, 0x95, 0xD2, 0x3E, 0x5B, 0x40, 0x83,
  0xB3, 0x69, 0x57, 0x1F, 0x07, 0x1C, 0x8A, 0xBC, 0x20, 0xEB, 0xCE, 0x8E, 0xAB, 0xEE, 0x31, 0xA2,
  0x73, 0xF9, 0xCA, 0x3A, 0x1A, 0xFB, 0x0D, 0xC1, 0xFE, 0xFA, 0xF2, 0x6F, 0xBD, 0x96, 0xDD, 0x43,
  0x52, 0xB6, 0x08, 0xF3, 0xAE, 0xBE, 0x19, 0x89, 0x32, 0x26, 0xB0, 0xEA, 0x4B, 0x64, 0x84, 0x82,
  0x6B, 0xF5, 0x79, 0xBF, 0x01, 0x5F, 0x75, 0x63, 0x1B, 0x23, 0x3D, 0x68, 0x2A, 0x65, 0xE8, 0x91,
  0xF6, 0xFF, 0x13, 0x58, 0xF1, 0x47, 0x0A, 0x7F, 0xC5, 0xA7, 0xE7, 0x61, 0x5A, 0x06, 0x46, 0x44,
  0x42, 0x04, 0xA0, 0xDB, 0x39, 0x86, 0x54, 0xAA, 0x8C, 0x34, 0x21, 0x8B, 0xF8, 0x0C, 0x74, 0x67
]

let pi3Box: [UInt8] = [
  0x68, 0x8D, 0xCA, 0x4D, 0x73, 0x4B, 0x4E, 0x2A, 0xD4, 0x52, 0x26, 0xB3, 0x54, 0x1E, 0x19, 0x1F,
  0x22, 0x03, 0x46, 0x3D, 0x2D, 0x4A, 0x53, 0x83, 0x13, 0x8A, 0xB7, 0xD5, 0x25, 0x79, 0xF5, 0xBD,
  0x58, 0x2F, 0x0D, 0x02, 0xED, 0x51, 0x9E, 0x11, 0xF2, 0x3E, 0x55, 0x5E, 0xD1, 0x16, 0x3C, 0x66,
  0x70, 0x5D, 0xF3, 0x45, 0x40, 0xCC, 0xE8, 0x94, 0x56, 0x08, 0xCE, 0x1A, 0x3A, 0xD2, 0xE1, 0xDF,
  0xB5, 0x38, 0x6E, 0x0E, 0xE5, 0xF4, 0xF9, 0x86, 0xE9, 0x4F, 0xD6, 0x85, 0x23, 0xCF, 0x32, 0x99,
  0x31, 0x14, 0xAE, 0xEE, 0xC8, 0x48, 0xD3, 0x30, 0xA1, 0x92, 0x41, 0xB1, 0x18, 0xC4, 0x2C, 0x71,
  0x72, 0x44, 0x15, 0xFD, 0x37, 0xBE, 0x5F, 0xAA, 0x9B, 0x88, 0xD8, 0xAB, 0x89, 0x9C, 0xFA, 0x60,
  0xEA, 0xBC, 0x62, 0x0C, 0x24, 0xA6, 0xA8, 0xEC, 0x67, 0x20, 0xDB, 0x7C, 0x28, 0xDD, 0xAC, 0x5B,
  0x34, 0x7E, 0x10, 0xF1, 0x7B, 0x8F, 0x63, 0xA0, 0x05, 0x9A, 0x43, 0x77, 0x21, 0xBF, 0x27, 0x09,
  0xC3, 0x9F, 0xB6, 0xD7, 0x29, 0xC2, 0xEB, 0xC0, 0xA4, 0x8B, 0x8C, 0x1D, 0xFB, 0xFF, 0xC1, 0xB2,
  0x97, 0x2E, 0xF8, 0x65, 0xF6, 0x75, 0x07, 0x04, 0x49, 0x33, 0xE4, 0xD9, 0xB9, 0xD0, 0x42, 0xC7,
  0x6C, 0x90, 0x00, 0x8E, 0x6F, 0x50, 0x01, 0xC5, 0xDA, 0x47, 0x3F, 0xCD, 0x69, 0xA2, 0xE2, 0x7A,
  0xA7, 0xC6, 0x93, 0x0F, 0x0A, 0x06, 0xE6, 0x2B, 0x96, 0xA3, 0x1C, 0xAF, 0x6A, 0x12, 0x84, 0x39,
  0xE7, 0xB0, 0x82, 0xF7, 0xFE, 0x9D, 0x87, 0x5C, 0x81, 0x35, 0xDE, 0xB4, 0xA5, 0xFC, 0x80, 0xEF,
  0xCB, 0xBB, 0x6B, 0x76, 0xBA, 0x5A, 0x7D, 0x78, 0x0B, 0x95, 0xE3, 0xAD, 0x74, 0x98, 0x3B, 0x36,
  0x64, 0x6D, 0xDC, 0xF0, 0x59, 0xA9, 0x4C, 0x17, 0x7F, 0x91, 0xB8, 0xC9, 0x57, 0x1B, 0xE0, 0x61
]
