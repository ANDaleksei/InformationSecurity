//
//  Methods.swift
//  EllipticCurve
//
//  Created by Oleksii Andriushchenko on 29.11.2020.
//

import Foundation
import BigInt

func generateFieldElement() -> BigInt {
  let t = 8
  let k = m / t + 1
  let rem = k * t - m
  var bytes = Array(0..<(k * t / 8)).map { _ in UInt8.random(in: (UInt8.min)...(UInt8.max)) }
  bytes[0] &= (1 << (8 - rem) - 1)
  return BigInt.init(bytes.map { String(format: "%02x", $0) }.joined(), radix: 16)!
}

// Private methods

private func calculateNewElement(u: BigInt) -> BigInt {
  return pow(u, power: 3) ^ A * pow(u, power: 2) ^ B
}

func generatePoint() -> Point {
  var u = generateFieldElement()
  var w = calculateNewElement(u: u)
  var z: BigInt?
  let root = solveSquareEquation(u: u, w: w)
  z = root
  while z == nil {
    u = generateFieldElement()
    w = calculateNewElement(u: u)
    let root = solveSquareEquation(u: u, w: w)
    z = root
  }
  return Point(x: u, y: z!)
}

/// Solve squrae equation
/// - Parameters:
///   - u: element of field
///   - w: element of field
/// - Returns: pairs of Int - count of roots, Element? - one of the roor (if count > 0)
private func solveSquareEquation(u: BigInt, w: BigInt) -> BigInt? {
  guard u != .zero else {
    return pow(w, power: 2 * (m - 1))
  }

  guard w != .zero else {
    return .zero
  }

  guard let uInv = u.inverse(polynom) else {
    return nil
  }

  let v = multiply(w, pow(uInv, power: 2))
  guard trace(v) != 1 else {
    return nil
  }

  let t = halfTrace(v)
  let z = multiply(t, u)
  return z
}

private func trace(_ x: BigInt) -> BigInt {
  var t = x
  for _ in 1..<m {
    t = multiply(t, t) ^ x
  }
  return t
}

private func halfTrace(_ x: BigInt) -> BigInt {
  var t = x
  for _ in 1...((m - 1) / 2) {
    t = pow(t, power: 4) ^ x
  }
  return t
}
