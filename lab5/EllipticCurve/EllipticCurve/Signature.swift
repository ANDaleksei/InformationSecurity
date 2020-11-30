//
//  Signature.swift
//  EllipticCurve
//
//  Created by Oleksii Andriushchenko on 30.11.2020.
//

import Foundation
import BigInt

final class Signature {

  let n = BigInt("400000000000000000002BEC12BE2262D39BCF14D", radix: 16)!
  let point = Point(
    x: BigInt("72D867F93A93AC27DF9FF01AFFE74885C8C540420", radix: 16)!,
    y: BigInt("0224A9C3947852B97C5599D5F4AB81122ADC3FD9B", radix: 16)!
  )
  let d: BigInt
  let q: Point
  let kupyna = Kupyna(s: 32)
  let e: BigInt
  let fe: BigInt

  init() {
    d = BigInt("183F60FDF7951FF47D67193F8D073790C1C9B5A3E", radix: 16)!
    q = mult(point, coef: d)
    let (e, fe) = makePresignature(point: point)
    self.e = e
    self.fe = fe
  }

  func sign(message: Data) -> (BigInt, BigInt) {
    let hashedData = kupyna.hash(data: message)
    let h = getFieldElement(from: hashedData)
    let r = multiply(h, fe)
    assert(r != 0)
    let s = (e ^ multiply(d, r))
    assert(s != 0)
    return (r, s)
  }

  func verify(message: Data, r: BigInt, s: BigInt) -> Bool {
    let hashedData = kupyna.hash(data: message)
    let h = getFieldElement(from: hashedData)
    let rPoint = mult(point, coef: s) + mult(q, coef: r)
    let rCheck = multiply(h, rPoint.x)
    let r = multiply(h, fe)
    return r == rCheck
  }

  private func getFieldElement(from data: Data) -> BigInt {
    return BigInt(data.map { String(format: "%02x", $0) }.joined(), radix: 16)!
  }

  private func getBasePoint() -> Point {
    while true {
      let point = generatePoint()
      for index in 2...200 {
        print("Check base \(index)")
        if mult(point, coef: BigInt(index)) == .zero {
          return point
        }
      }
    }
  }
}

private func makePresignature(point: Point) -> (e: BigInt, fe: BigInt) {
  var e = generateFieldElement()
  var r = mult(point, coef: e)
  while r.x == 0 {
    e = generateFieldElement()
    r = mult(point, coef: e)
  }
  return (e: e, fe: r.x)
}
