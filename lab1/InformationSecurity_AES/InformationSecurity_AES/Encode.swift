//
//  Encode.swift
//  InformationSecurity_AES
//
//  Created by Oleksii Andriushchenko on 01.10.2020.
//

import Foundation

enum Constants {
  // number of columns
  static let Nb = 4
  // number of rounds
  static let Nr = 10
  //
  static let Nk = 4
}

final class AesAlgorithm {

  private var words: [[UInt8]] = []

  init(key: String) {
    self.words = keyExpansion(key: key.data(using: .utf8)!.map { $0 })
  }

  init(key: Data) {
    self.words = keyExpansion(key: key.map { $0 })
  }

  func encode(text: String) -> Data {
    guard let data = text.data(using: .utf8) else {
      fatalError("Can't get data from input text")
    }

    return encode(data: data)
  }

  func encode(data: Data) -> Data {
    var iter = 0
    var result = Data()
    while 16 * (iter + 1) <= data.count  {
      do {
        let output = try encodeBlock(input: data[(16 * iter)..<(16 * (iter + 1))])
        result.append(output)
      } catch {
        fatalError(error.localizedDescription)
      }

      iter += 1
    }

    return result
  }

  func decode(data: Data) -> String {
    return String(data: decode(data: data), encoding: .utf8)!
  }

  func decode(data: Data) -> Data {
    var iter = 0
    var result = Data()
    while 16 * (iter + 1) <= data.count  {
      do {
        let output = try decodeBlock(input: Data(Array(data[(16 * iter)..<(16 * (iter + 1))])))
        result.append(output)
      } catch {
        fatalError(error.localizedDescription)
      }

      iter += 1
    }

    return result
  }

  // MARK: Encode

  private func encodeBlock(input: Data) throws -> Data {
    guard input.count == 16 else {
      throw AESError.badInput("Input should be exactly 16 bytes")
    }

    var state = createState(from: input)
    addRoundKey(state: &state, words: Array(words[0..<Constants.Nb]))

    for round in 1..<(Constants.Nr) {
      subBytes(state: &state)
      shiftRows(state: &state)
      mixColumns(state: &state)
      addRoundKey(state: &state, words: Array(words[(round * Constants.Nb)..<((round + 1) * Constants.Nb)]))
    }

    subBytes(state: &state)
    shiftRows(state: &state)
    addRoundKey(
      state: &state,
      words: Array(words[(Constants.Nr * Constants.Nb)..<((Constants.Nr + 1) * Constants.Nb)])
    )

    let output = createOutput(from: state)
    return output
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
    let transposeWords = words.indices.map { index in words.map { $0[index] } }
    state[0] = xor(lhs: state[0], rhs: transposeWords[0])
    state[1] = xor(lhs: state[1], rhs: transposeWords[1])
    state[2] = xor(lhs: state[2], rhs: transposeWords[2])
    state[3] = xor(lhs: state[3], rhs: transposeWords[3])
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
    for columnIndex in 0..<state[0].count {
      let column = state.map { $0[columnIndex] }
      state[0][columnIndex] = multiplyBy2(byte: column[0])
        ^ multiplyBy3(byte: column[1])
        ^ column[2]
        ^ column[3]
      state[1][columnIndex] = column[0]
        ^ multiplyBy2(byte: column[1])
        ^ multiplyBy3(byte: column[2])
        ^ column[3]
      state[2][columnIndex] = column[0]
        ^ column[1]
        ^ multiplyBy2(byte: column[2])
        ^ multiplyBy3(byte: column[3])
      state[3][columnIndex] = multiplyBy3(byte: column[0])
        ^ column[1]
        ^ column[2]
        ^ multiplyBy2(byte: column[3])
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


  func SboxSubstitution(byte: UInt8) -> UInt8 {
    return box[Int(byte)]
  }

  func rotWord(word: [UInt8]) -> [UInt8] {
    return [word[1], word[2], word[3], word[0]]
  }

  // MARK: - Decode

  private func decodeBlock(input: Data) throws -> Data {
    guard input.count == 16 else {
      throw AESError.badInput("Input should be exactly 16 bytes")
    }

    var state = createState(from: input)
    addRoundKey(
      state: &state,
      words: Array(words[(Constants.Nr * Constants.Nb)..<((Constants.Nr + 1) * Constants.Nb)])
    )

    for round in 1..<Constants.Nr {
      let invRound = Constants.Nr - round
      invShiftRows(state: &state)
      invSubBytes(state: &state)
      addRoundKey(state: &state, words: Array(words[(invRound * Constants.Nb)..<((invRound + 1) * Constants.Nb)]))
      invMixColumns(state: &state)
    }

    invShiftRows(state: &state)
    invSubBytes(state: &state)
    addRoundKey(state: &state, words: Array(words[0..<Constants.Nb]))

    let output = createOutput(from: state)
    return output
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
      state[0][columnIndex] = multiplyBy14(byte: column[0])
        ^ multiplyBy11(byte: column[1])
        ^ multiplyBy13(byte: column[2])
        ^ multiplyBy9(byte: column[3])
      state[1][columnIndex] = multiplyBy9(byte: column[0])
        ^ multiplyBy14(byte: column[1])
        ^ multiplyBy11(byte: column[2])
        ^ multiplyBy13(byte: column[3])
      state[2][columnIndex] = multiplyBy13(byte: column[0])
        ^ multiplyBy9(byte: column[1])
        ^ multiplyBy14(byte: column[2])
        ^ multiplyBy11(byte: column[3])
      state[3][columnIndex] = multiplyBy11(byte: column[0])
        ^ multiplyBy13(byte: column[1])
        ^ multiplyBy9(byte: column[2])
        ^ multiplyBy14(byte: column[3])
    }
  }

  private func invSboxSubstitution(byte: UInt8) -> UInt8 {
    return invBox[Int(byte)]
  }

  // MARK: - Key expansion

  private func keyExpansion(key: [UInt8]) -> [[UInt8]] {

    var words = [[UInt8]](repeating: [UInt8](repeating: 0, count: Constants.Nk), count: Constants.Nb * (Constants.Nr + 1))

    var iter = 0
    while iter < Constants.Nk {
      words[iter] = [key[4 * iter], key[4 * iter + 1], key[4 * iter + 2], key[4 * iter + 3]]
      iter += 1
    }

    iter = Constants.Nk

    while iter < Constants.Nb * (Constants.Nr + 1) {
      var word = words[iter - 1]
      if iter % Constants.Nk == 0 {
        word = xor(lhs: SboxSubstitution(word: rotWord(word: word)), rhs: Rcon[iter / Constants.Nk])
      } else if Constants.Nk > 6 && iter % Constants.Nk == 4 {
        word = SboxSubstitution(word: word)
      }
      words[iter] = xor(lhs: words[iter - Constants.Nk], rhs: word)
      iter += 1
    }

    return words
  }

  private func SboxSubstitution(word: [UInt8]) -> [UInt8] {
    return word.map(SboxSubstitution(byte:))
  }
}



