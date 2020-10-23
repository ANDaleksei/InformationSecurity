//
//  main.swift
//  CryptographicHashFunctions
//
//  Created by Oleksii Andriushchenko on 23.10.2020.
//

import Foundation

let sha256 = SHA256()
let data = sha256.hash(data: Array(repeating: "a", count: 1000000).joined().data(using: .utf8)!)
for byte in data {
  print(String(format: "%02x", byte), terminator: "")
}
print()

testSHA256_case1()
testSHA256_case2()
