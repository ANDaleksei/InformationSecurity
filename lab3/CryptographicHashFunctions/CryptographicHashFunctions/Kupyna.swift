//
//  Kupyna.swift
//  CryptographicHashFunctions
//
//  Created by Oleksii Andriushchenko on 24.10.2020.
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

  func mappingTXor(bytes: [UInt8]) -> [UInt8] {
    var state = makeState(bytes: bytes)
    for round in 0..<k {
      addModulo2(state: &state, round: round)
      subBytes(state: &state)
      shiftRows(state: &state)
      linearTransformation(state: &state)
    }
    return state.flatMap { $0 }
  }

  func mappingTPlus(bytes: [UInt8]) -> [UInt8] {
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
