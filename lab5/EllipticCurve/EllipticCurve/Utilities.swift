//
//  Utilities.swift
//  EllipticCurve
//
//  Created by Oleksii Andriushchenko on 29.11.2020.
//

import Foundation
import BigInt

let A = BigInt("1")
let B = BigInt("5FF6108462A2DC8210AB403925E638A19C1455D21", radix: 16)!
let m = 163
let polynom = BigInt(2).power(163) + BigInt(2).power(7) + BigInt(2).power(6) + BigInt(2).power(3) + BigInt(1)
let half = BigInt(2).power(162)
// number of bytes each element should have
let bytesCount = m / 8 + 1
// first byte of each element shouldn't be more than mask (becaus of field size)
let maskByte: UInt8 = 7

func mult(_ point: Point, coef: BigInt) -> Point {
  assert(coef >= 0)
  var res = Point.zero
  var k = coef
  while k > 0 {
    res = res.double()
    if k % 2 == 1 {
      res = res + point
    }
    k /= 2
  }
  return res
//  if coef == 0 {
//    return .zero
//  } else if coef == 1 {
//    return point
//  } else if coef % 2 == 0 {
//    return mult(point.double(), coef: coef / 2)
//  } else {
//    return point + mult(point.double(), coef: (coef - 1) / 2)
//  }
}

func pow(_ elem: BigInt, power: Int) -> BigInt {
  assert(power >= 0)
  if power == 0 {
    return BigInt(1)
  } else if power == 1 {
    return elem
  } else if power % 2 == 0 {
    return pow(multiply(elem, elem), power: power / 2)
  } else {
    return multiply(elem, pow(multiply(elem, elem), power: (power - 1) / 2))
  }
}

func multiply(_ lhs: BigInt, _ rhs: BigInt) -> BigInt {
  var result = BigInt(0)
  var left: BigInt = lhs
  var right: BigInt = rhs
  while left > 0 && right > 0 {
    if right & 1 != 0 {
      result ^= left
    }

    if left > half {
      left = (left << 1) ^ polynom
    } else {
      left <<= 1
    }
    right >>= 1
  }
  return result
}

//func pow(_ elem: Element, power: Int) -> Element {
//  assert(power >= 0)
//  if power == 0 {
//    return Element(bytes: [1])
//  } else if power == 1 {
//    return elem
//  } else if power % 2 == 0 {
//    return pow(elem * elem, power: power / 2)
//  } else {
//    return elem * pow(elem * elem, power: (power - 1) / 2)
//  }
//}
