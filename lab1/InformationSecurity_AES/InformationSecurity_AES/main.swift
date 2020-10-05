//
//  main.swift
//  InformationSecurity_AES
//
//  Created by Oleksii Andriushchenko on 28.09.2020.
//

import Foundation

let inputText = "Hello world word"
let key = "0123456789abcdef"

let aesText = AesAlgorithm(key: key)
let dataText = aesText.encode(text: inputText)
let decodedText: String = aesText.decode(data: dataText)
print(decodedText)

let dataKey = Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
let inputData = Data([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
let aesData = AesAlgorithm(key: dataKey)
let data = aesData.encode(data: inputData)
let decodedData: Data = aesData.decode(data: data)
print(decodedData.map { $0 })
