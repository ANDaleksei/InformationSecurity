//
//  RSA.swift
//  Cryptosystems
//
//  Created by Oleksii Andriushchenko on 12.11.2020.
//

import BigNumber
import Foundation

struct Key {
  let exp: BInt
  let modul: BInt
}

final class RSA {

  let primeNumbers: (p: BInt, q: BInt)
  let publicKey: Key
  let privateKey: Key
  let nBitsCount: Int

  init(bitCount: Int) {
    let data = generateKeys(bitCount: bitCount)
    self.primeNumbers = data.numbers
    self.publicKey = data.publicKey
    self.privateKey = data.privateKey
    self.nBitsCount = getBitsCount(modul: data.publicKey.modul)
    print("RSA can work with data of \(nBitsCount - 1) bits count max")
  }

  func encrypt(data: Data) -> Data {
    assert(data.count * 8 < nBitsCount)
    return power(data: data, key: publicKey)
  }

  func decrypt(data: Data) -> Data {
    let number = data.reduce(BInt(0), { BInt(256) * $0 + BInt($1) })

    let p = primeNumbers.p
    let q = primeNumbers.q
    let d = privateKey.exp
    let dp = d % (p - 1)
    let dq = d % (q - 1)
    var (qInv, _, _) = gcd(a: q, b: p)
    if qInv < 0 {
      qInv += p
    }
    let mp = Cryptosystems.power(base: number, pow: dp, modul: p)
    let mq = Cryptosystems.power(base: number, pow: dq, modul: q)
    let h = (qInv * ((mp + privateKey.modul - mq) % privateKey.modul)) % p
    let res = (mq + h * q) % privateKey.modul
    return getData(from: res)
  }

  private func power(data: Data, key: Key) -> Data {
    let number = data.reduce(BInt(0), { BInt(256) * $0 + BInt($1) })
    let res = Cryptosystems.power(base: number, pow: key.exp, modul: key.modul)
    return getData(from: res)
  }

  private func getData(from number: BInt) -> Data {
    var number = number
    var result = Data()
    while number > 0 {
      let block = number % 256
      result.insert(UInt8(block), at: 0)
      number /= 256
    }
    return result
  }
}

private func generateKeys(bitCount: Int) -> (numbers: (BInt, BInt), privateKey: Key, publicKey: Key) {
  let p: BInt
  let q: BInt
  if bitCount == 512 {
    p = BInt("8900543240482997754914162044025767982635627519343459756728976360080718086381430676688651765068519047576132957558436321163510739964410181269608508885633461")!
    q = BInt("10202766040255127271125425654523124798174533366051360568713040811498275114109338135715156609748318552691463701476718163519911834599980746685789117212304651")!
  } else {
    p = findPrimeNumber(bitCount: bitCount)
    q = findPrimeNumber(bitCount: bitCount)
  }
  let n = p * q
  let phi = (p - 1) * (q - 1)
  let e = BInt(65537)
  var (d, _, _) = gcd(a: e, b: phi)
  if d < 0 {
    d += phi
  }
  print("d = \(d)")
  let privateKey = Key(exp: d, modul: n)
  let publicKey = Key(exp: e, modul: n)
  return ((p, q), privateKey, publicKey)
}

private func findPrimeNumber(bitCount: Int) -> BInt {
  let firstDigit = String("123456789".randomElement()!)
  let otherDigitsCount = bitCount * 3 / 10
  let lastDigit = String("13579".randomElement()!)
  let otherDigits = String(Array(0..<otherDigitsCount) .map { _ in "0123456789".randomElement()! })
  let stringNum = firstDigit + otherDigits + lastDigit
  var number = BInt(stringNum)!
  repeat {
    if checkIsPrime(number: number) {
      return number
    } else {
      number += 2
    }
  } while true
}

private func gcd(a: BInt, b: BInt) -> (x: BInt, y: BInt, d: BInt) {
  guard a != 0 else {
    return (x: 0, y: 1, d: b)
  }

  let (x1, y1, d) = gcd(a: b % a, b: a)
  let x = y1 - (b / a) * x1
  let y = x1
  return (x: x, y: y, d: d)
}

private func getBitsCount(modul: BInt) -> Int {
  var number = modul
  var count = 0
  while number > 0 {
    number /= 2
    count += 1
  }
  return count
}
