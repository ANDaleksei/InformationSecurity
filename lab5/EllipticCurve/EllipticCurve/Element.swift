//
//  Element.swift
//  EllipticCurve
//
//  Created by Oleksii Andriushchenko on 29.11.2020.
//

import Foundation

struct Element {

  fileprivate var bytes: [UInt8]

  init(text: String) {
    var bytes = getBytes(from: text)
    assert(bytes.count <= bytesCount)
    while bytes.count < bytesCount {
      bytes.insert(.zero, at: 0)
    }
    self.bytes = bytes
  }

  init(bytes: [UInt8]) {
    var bytes = bytes
    assert(bytes.count <= bytesCount)
    while bytes.count < bytesCount {
      bytes.insert(.zero, at: 0)
    }
    self.bytes = bytes
  }

  // element % 2 == 1 or element & 1 != 0
  var isOdd: Bool {
    return bytes.last! & 1 != 0
  }

  var description: String {
    return bytes.map { String(format: "%02x", $0) }.joined()
  }

  static func + (lhs: Element, rhs: Element) -> Element {
    assert(lhs.bytes.count == rhs.bytes.count)
    return Element(bytes: zip(lhs.bytes, rhs.bytes).map { $0 ^ $1 })
  }

  static func * (lhs: Element, rhs: Element) -> Element {
    var result = Element(bytes: [.zero])
    var left: Element = lhs
    var right: Element = rhs
    while left > .zero && right > .zero {
      if right.isOdd {
        result ^= left
      }

      if left.bytes.first! & 0x04 != 0 {
        left = (left << 1) ^ .polynom
      } else {
        left <<= 1
      }
      right >>= 1
    }
    return result
  }

  static func ^ (lhs: Element, rhs: Element) -> Element {
    assert(lhs.bytes.count == rhs.bytes.count)
    return Element(bytes: zip(lhs.bytes, rhs.bytes).map { $0 ^ $1 })
  }

  static func ^= (lhs: inout Element, rhs: Element) {
    assert(lhs.bytes.count == rhs.bytes.count)
    lhs.bytes = zip(lhs.bytes, rhs.bytes).map { $0 ^ $1 }
  }

  static func << (lhs: Element, rhs: Int) -> Element {
    assert(rhs <= 8)
    var result = Element.zero
    for index in 0..<lhs.bytes.count {
      result.bytes[index] = lhs.bytes[index] << rhs
      if index != lhs.bytes.count - 1 {
        let next = lhs.bytes[index + 1] >> (8 - rhs)
        result.bytes[index] ^= next
      }
    }
    return result
  }

  static func <<= (lhs: inout Element, rhs: Int) {
    assert(rhs <= 8)
    for index in 0..<lhs.bytes.count {
      lhs.bytes[index] <<= rhs
      if index != lhs.bytes.count - 1 {
        let next = lhs.bytes[index + 1] >> (8 - rhs)
        lhs.bytes[index] ^= next
      }
    }
  }

  static func >>= (lhs: inout Element, rhs: Int) {
    assert(rhs <= 8)
    for index in 0..<lhs.bytes.count {
      let inverseIndex = lhs.bytes.count - index - 1
      lhs.bytes[inverseIndex] >>= rhs
      if inverseIndex != 0 {
        let prev = lhs.bytes[inverseIndex - 1] << (8 - rhs)
        lhs.bytes[inverseIndex] ^= prev
      }
    }
  }

  static var zero: Element {
    return .init(bytes: [.zero])
  }

  static var polynom: Element {
    return .init(bytes: [0xc9])
  }
}

extension Element: Equatable {
  static func == (lhs: Element, rhs: Element) -> Bool {
    return zip(lhs.bytes, rhs.bytes).allSatisfy { $0 == $1 }
  }
}

extension Element: Comparable {
  static func < (lhs: Element, rhs: Element) -> Bool {
    let pairs = zip(lhs.bytes, rhs.bytes)
    guard let pair = pairs.first(where: { $0 != $1 }) else {
      return false
    }

    return pair.0 < pair.1
  }
}

private func getBytes(from text: String) -> [UInt8] {
  var hexString = text
  if text.count % 2 == 1 {
    hexString.insert("0", at: hexString.startIndex)
  }
  var bytes = [UInt8]()
  bytes.reserveCapacity(hexString.count / 2)
  var index = hexString.endIndex
  for _ in 0..<(hexString.count / 2) {
    let prevIndex = hexString.index(index, offsetBy: -2)
    if let b = UInt8(hexString[prevIndex..<index], radix: 16) {
      bytes.insert(b, at: 0)
    } else {
      return []
    }
    index = prevIndex
  }
  return bytes
}
