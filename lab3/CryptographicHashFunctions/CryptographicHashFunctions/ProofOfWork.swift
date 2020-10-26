//
//  ProofOfWork.swift
//  CryptographicHashFunctions
//
//  Created by Oleksii Andriushchenko on 26.10.2020.
//

import Foundation

func proofOfWorkSHA256() {
  let hasher = SHA256()
  print("Proof of work for SHA-256")
  for zeroCount in 1..<32 {
    print("Start searching for \(zeroCount) bit zeros.")
    let startTime = CFAbsoluteTimeGetCurrent()
    for index in 0..<Int.max {
      let data = "".data(using: .utf8)! + getData(from: index)
      let hash = hasher.hash(data: data)
      if isSatisfied(hash: hash, zeroCount: zeroCount, index: index) {
        break
      }
    }
    let timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
    print("Success result, time taken in seconds: \(timeElapsed)")
  }
}

func proofOfWorkKypuna256() {
  let hasher = Kupyna(s: 32)
  print("Proof of work for Kupyna-256")
  for zeroCount in 1..<32 {
    print("Start searching for \(zeroCount) bit zeros.")
    let startTime = CFAbsoluteTimeGetCurrent()
    for index in 0..<Int.max {
      let data = "".data(using: .utf8)! + getData(from: index)
      let hash = hasher.hash(data: data)
      if isSatisfied(hash: hash, zeroCount: zeroCount, index: index) {
        break
      }
    }
    let timeElapsed = CFAbsoluteTimeGetCurrent() - startTime
    print("Success result, time taken in seconds: \(timeElapsed)")
  }
}

func getData(from number: Int) -> Data {
  var result: [UInt8] = []
  for index in 0..<8 {
    let shiftedWord = number >> (8 * (7 - index))
    let byte = UInt8(shiftedWord & 0xff)
    result.append(byte)
  }
  return Data(result)
}

private func isSatisfied(hash: Data, zeroCount: Int, index: Int) -> Bool {
  let zeroByteCount = zeroCount / 8
  let zeroBitCount = zeroCount % 8
  if hash.prefix(zeroByteCount).allSatisfy({ $0 == 0 }) && (zeroBitCount == 0 || hash[zeroByteCount] < (1 << (8 - zeroBitCount))) {
    printDebug(hash: hash, zeroCount: zeroCount, index: index)
    return true
  } else {
    return false
  }
}

private func printDebug(hash: Data, zeroCount: Int, index: Int) {
  print("Added number \(index)")
  print("Hash:")
  for byte in hash {
    print(String(format: "%02x", byte), terminator: "")
  }
  print()
}
