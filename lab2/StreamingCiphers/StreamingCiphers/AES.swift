//
//  AES.swift
//  StreamingCiphers
//
//  Created by Oleksii Andriushchenko on 18.10.2020.
//

import Foundation

final class AesAlgorithm {

  struct Config {
    let keyLength: Int
    let words: Int
    let rounds: Int

    var columns: Int {
      return keyLength / (8 * words)
    }

    var keyByteLength: Int {
      return keyLength / 8
    }

    static var config128: Config {
      return .init(keyLength: 128, words: 4, rounds: 10)
    }

    static var config192: Config {
      return .init(keyLength: 192, words: 6, rounds: 12)
    }

    static var config256: Config {
      return .init(keyLength: 256, words: 8, rounds: 14)
    }
  }

  private let config: Config
  private var words: [[UInt8]] = []

  init(key: Data, config: Config = .config128) {
    self.config = config
    setupMultiplyTable()
    self.words = keyExpansion(key: key.map { $0 })
  }

  // MARK: Encrypt

  func encodeBlock(data: Data) -> Data {
    guard data.count == 16 else {
      fatalError("Input should be exactly 16 bytes")
    }

    var state = createState(from: data)
    addRoundKey(state: &state, words: Array(words[0..<config.columns]))

    for round in 1..<(config.rounds) {
      subBytes(state: &state)
      shiftRows(state: &state)
      mixColumns(state: &state)
      addRoundKey(state: &state, words: Array(words[(round * config.columns)..<((round + 1) * config.columns)]))
    }

    subBytes(state: &state)
    shiftRows(state: &state)
    addRoundKey(
      state: &state,
      words: Array(words[(config.rounds * config.columns)..<((config.rounds + 1) * config.columns)])
    )

    return createOutput(from: state)
  }

  private func createState(from input: Data) -> [[UInt8]] {
    var result: [[UInt8]] = []
    for row in 0..<4 {
      var rowResult: [UInt8] = []
      for column in 0..<4 {
        rowResult.append(input[row + 4 * column])
      }
      result.append(rowResult)
    }
    return result
  }

  private func addRoundKey(state: inout [[UInt8]], words: [[UInt8]]) {
    state[0] = xor(lhs: state[0], rhs: [words[0][0], words[1][0], words[2][0], words[3][0]])
    state[1] = xor(lhs: state[1], rhs: [words[0][1], words[1][1], words[2][1], words[3][1]])
    state[2] = xor(lhs: state[2], rhs: [words[0][2], words[1][2], words[2][2], words[3][2]])
    state[3] = xor(lhs: state[3], rhs: [words[0][3], words[1][3], words[2][3], words[3][3]])
  }

  private func subBytes(state: inout [[UInt8]]) {
    for row in 0..<state.count {
      for column in 0..<state[row].count {
        state[row][column] = SboxSubstitution(byte: state[row][column])
      }
    }
  }

  private func shiftRows(state: inout [[UInt8]]) {
    for row in 1..<state.count {
      state[row].shift(by: row)
    }
  }

  private func mixColumns(state: inout [[UInt8]]) {
    let copy = state
    for columnIndex in 0..<state[0].count {
      state[0][columnIndex] = multiply2Table[Int(copy[0][columnIndex])]
        ^ multiply3Table[Int(copy[1][columnIndex])]
        ^ copy[2][columnIndex]
        ^ copy[3][columnIndex]
      state[1][columnIndex] = copy[0][columnIndex]
        ^ multiply2Table[Int(copy[1][columnIndex])]
        ^ multiply3Table[Int(copy[2][columnIndex])]
        ^ copy[3][columnIndex]
      state[2][columnIndex] = copy[0][columnIndex]
        ^ copy[1][columnIndex]
        ^ multiply2Table[Int(copy[2][columnIndex])]
        ^ multiply3Table[Int(copy[3][columnIndex])]
      state[3][columnIndex] = multiply3Table[Int(copy[0][columnIndex])]
        ^ copy[1][columnIndex]
        ^ copy[2][columnIndex]
        ^ multiply2Table[Int(copy[3][columnIndex])]
    }
  }

  private func createOutput(from state: [[UInt8]]) -> Data {
    var output = Data(count: 16)
    for row in 0..<4 {
      for column in 0..<4 {
        output[row + 4 * column] = state[row][column]
      }
    }
    return output
  }


  private func SboxSubstitution(byte: UInt8) -> UInt8 {
    return box[Int(byte)]
  }

  private func rotWord(word: [UInt8]) -> [UInt8] {
    return [word[1], word[2], word[3], word[0]]
  }

  // MARK: - Decrypt

  func decodeBlock(data: Data) -> Data {
    guard data.count == 16 else {
      fatalError("Input should be exactly 16 bytes")
    }

    var state = createState(from: data)
    addRoundKey(
      state: &state,
      words: Array(words[(config.rounds * config.columns)..<((config.rounds + 1) * config.columns)])
    )

    for round in 1..<config.rounds {
      let invRound = config.rounds - round
      invShiftRows(state: &state)
      invSubBytes(state: &state)
      addRoundKey(state: &state, words: Array(words[(invRound * config.columns)..<((invRound + 1) * config.columns)]))
      invMixColumns(state: &state)
    }

    invShiftRows(state: &state)
    invSubBytes(state: &state)
    addRoundKey(state: &state, words: Array(words[0..<config.columns]))

    return createOutput(from: state)
  }

  private func invSubBytes(state: inout [[UInt8]]) {
    for row in 0..<state.count {
      for column in 0..<state[row].count {
        state[row][column] = invSboxSubstitution(byte: state[row][column])
      }
    }
  }

  private func invShiftRows(state: inout [[UInt8]]) {
    for row in 1..<state.count {
      state[row].shift(by: state[0].count - row)
    }
  }

  private func invMixColumns(state: inout [[UInt8]]) {
    for columnIndex in 0..<state[0].count {
      let column = state.map { $0[columnIndex] }
      state[0][columnIndex] = multiply14Table[Int(column[0])]
        ^ multiply11Table[Int(column[1])]
        ^ multiply13Table[Int(column[2])]
        ^ multiply9Table[Int(column[3])]
      state[1][columnIndex] = multiply9Table[Int(column[0])]
        ^ multiply14Table[Int(column[1])]
        ^ multiply11Table[Int(column[2])]
        ^ multiply13Table[Int(column[3])]
      state[2][columnIndex] = multiply13Table[Int(column[0])]
        ^ multiply9Table[Int(column[1])]
        ^ multiply14Table[Int(column[2])]
        ^ multiply11Table[Int(column[3])]
      state[3][columnIndex] = multiply11Table[Int(column[0])]
        ^ multiply13Table[Int(column[1])]
        ^ multiply9Table[Int(column[2])]
        ^ multiply14Table[Int(column[3])]
    }
  }

  private func invSboxSubstitution(byte: UInt8) -> UInt8 {
    return invBox[Int(byte)]
  }

  // MARK: - Key expansion

  private func keyExpansion(key: [UInt8]) -> [[UInt8]] {

    var words = [[UInt8]](repeating: [UInt8](repeating: 0, count: config.words), count: config.columns * (config.rounds + 1))

    var iter = 0
    while iter < config.words {
      words[iter] = [key[4 * iter], key[4 * iter + 1], key[4 * iter + 2], key[4 * iter + 3]]
      iter += 1
    }

    iter = config.words

    while iter < (config.columns * (config.rounds + 1)) {
      var word = words[iter - 1]
      if iter % config.words == 0 {
        word = xor(lhs: SboxSubstitution(word: rotWord(word: word)), rhs: Rcon[iter / config.words])
      } else if config.words > 6 && iter % config.words == 4 {
        word = SboxSubstitution(word: word)
      }
      words[iter] = xor(lhs: words[iter - config.words], rhs: word)
      iter += 1
    }

    return words
  }

  private func SboxSubstitution(word: [UInt8]) -> [UInt8] {
    return word.map(SboxSubstitution(byte:))
  }

  // Utilities

  private var multiply2Table: [UInt8] = .init(repeating: 0, count: 256)
  private var multiply3Table: [UInt8] = .init(repeating: 0, count: 256)
  private var multiply9Table: [UInt8] = .init(repeating: 0, count: 256)
  private var multiply11Table: [UInt8] = .init(repeating: 0, count: 256)
  private var multiply13Table: [UInt8] = .init(repeating: 0, count: 256)
  private var multiply14Table: [UInt8] = .init(repeating: 0, count: 256)
  private func setupMultiplyTable() {
    for num in 0..<256 {
      multiply2Table[num] = multiplyBy2(byte: UInt8(num))
      multiply3Table[num] = multiplyBy3(byte: UInt8(num))
      multiply9Table[num] = multiplyBy9(byte: UInt8(num))
      multiply11Table[num] = multiplyBy11(byte: UInt8(num))
      multiply13Table[num] = multiplyBy13(byte: UInt8(num))
      multiply14Table[num] = multiplyBy14(byte: UInt8(num))
    }
  }
}
