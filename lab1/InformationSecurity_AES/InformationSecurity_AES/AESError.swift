//
//  AESError.swift
//  InformationSecurity_AES
//
//  Created by Oleksii Andriushchenko on 01.10.2020.
//

import Foundation

enum AESError {
  case badInput(String)
}

extension AESError: LocalizedError {
  var errorDescription: String? {
    switch self {
    case .badInput(let message):
      return "Bad input: \(message)"
    }
  }
}
