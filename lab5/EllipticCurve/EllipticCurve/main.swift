//
//  main.swift
//  EllipticCurve
//
//  Created by Oleksii Andriushchenko on 29.11.2020.
//

import Foundation
import BigInt

let hello = "Hello world"
let signatureAlgo = Signature()
let signature = signatureAlgo.sign(message: hello.data(using: .utf8)!)
print(signature)
print(signatureAlgo.verify(message: hello.data(using: .utf8)!, r: signature.0, s: signature.1))

let n = BigInt("400000000000000000002BEC12BE2262D39BCF14D", radix: 16)!
let point = Point(
  x: BigInt("72D867F93A93AC27DF9FF01AFFE74885C8C540420", radix: 16)!,
  y: BigInt("0224A9C3947852B97C5599D5F4AB81122ADC3FD9B", radix: 16)!
)

let newPoint = generatePoint()
print((pow(newPoint.y, power: 2) ^ multiply(newPoint.x, newPoint.y)).description)
print((pow(newPoint.x, power: 3) ^ multiply(A, pow(newPoint.x, power: 2)) ^ B).description)

print((pow(point.y, power: 2) ^ multiply(point.x, point.y)).description)
print((pow(point.x, power: 3) ^ multiply(A, pow(point.x, power: 2)) ^ B).description)
//print(mult(point, coef: n).description)
let res = point + point
print(res.description)
//print(mult(point, coef: 2).description)
print((pow(res.y, power: 2) ^ multiply(res.x, res.y)).description)
print((pow(res.x, power: 3) ^ multiply(A, pow(res.x, power: 2)) ^ B).description)

//let e = BigInt("1025E40BD97DB012B7A1D79DE8E12932D247F61C6", radix: 16)!
//print(mult(point, coef: e).description)
