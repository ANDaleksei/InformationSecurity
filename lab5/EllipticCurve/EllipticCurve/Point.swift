//
//  Point.swift
//  EllipticCurve
//
//  Created by Oleksii Andriushchenko on 30.11.2020.
//

import Foundation
import BigInt

struct Point: Equatable {
  let x: BigInt
  let y: BigInt

  var description: String {
    let xDescription = x.serialize().map { String.init(format: "%02x", $0) }.joined()
    let yDescription = y.serialize().map { String.init(format: "%02x", $0) }.joined()
    return "Point(x: \(xDescription), y: \(yDescription)"
  }

  static func + (lhs: Point, rhs: Point) -> Point {
    guard lhs != .zero else {
      return rhs
    }

    guard rhs != .zero else {
      return lhs
    }

    if lhs.x == rhs.x && rhs.y == lhs.x ^ lhs.y {
      return .zero
    } else if lhs.x != rhs.x {
      let l = (lhs.y ^ rhs.y) / (lhs.x ^ rhs.x)
      let x = pow(l, power: 2) ^ l ^ lhs.x ^ rhs.x ^ A
      let y = multiply(l, (lhs.x ^ x)) ^ x ^ lhs.y
      return .init(
        x: x,
        y: y
      )
    } else if lhs.x == rhs.x && lhs.y == rhs.y {
      let m = lhs.x ^ lhs.y / rhs.x
      let x = pow(m, power: 2) ^ m ^ A
      return .init(
        x: x,
        y: pow(lhs.x, power: 2) ^ multiply((m ^ 1), x)
      )
    } else {
      fatalError()
    }
  }

  func double() -> Point {
    guard self.x != 0 else {
      return .zero
    }

    let m = self.x ^ self.y / self.x
    let x = pow(m, power: 2) ^ m ^ A
    return .init(
      x: x,
      y: pow(self.x, power: 2) ^ multiply((m ^ 1), x)
    )
//    let x = pow(self.x, power: 2) ^ (B / pow(self.x, power: 2))
//    let y = pow(self.x, power: 2) ^ multiply((self.x ^ (self.y / self.x)), x) ^ x
//    return .init(
//      x: x,
//      y: y
//    )
  }

  static var zero: Point {
    return .init(x: 0, y: 0)
  }
}
