//
//  MillerRabinTest.swift
//  Cryptosystems
//
//  Created by Oleksii Andriushchenko on 12.11.2020.
//

import BigNumber
import Foundation

func checkIsPrime(number: BInt) -> Bool {
  let (s, t) = getTwoNumbers(from: number - 1)
  //print("\(number - 1) = 2^(\(s)) * \(t)")
  let k = log2(number: number)
  //print("Number of rounds: \(k)")
  //print("Random numbers: ", terminator: "")
  for _ in 0..<k {
    // get random number from 0 to 2^64 because BInt doesn't have this functionality
    let a = BInt(Int.random(in: 1...(number < Int.max ? Int(number) : Int.max)))
    var x = power(base: a, pow: t, modul: number)
    if x == 1 || x == number - 1 {
      continue
    }
    var shouldContinue = false
    for _ in 0..<s {
      x = (x * x) % number
      if x == number - 1 {
        shouldContinue = true
        break
      }
    }
    if !shouldContinue {
      return false
    }
  }
  return true
}

private func getTwoNumbers(from number: BInt) -> (s: BInt, t: BInt) {
  var s = BInt(0)
  var t = number
  while t % 2 == 0 {
    s += 1
    t /= 2
  }
  return (s: s, t: t)
}

private func log2(number: BInt) -> BInt {
  var res = BInt(2)
  var power = BInt(0)
  while res <= number {
    res *= 2
    power += 1
  }
  return power
}

func power(base: BInt, pow: BInt, modul: BInt) -> BInt {
  var res = BInt(1)
  var exp = pow
  var base = base
  while exp > 0 {
    if exp % 2 == 1 {
      res = (res * base) % modul
    }
    base = (base * base) % modul;
    exp /= 2
  }
  return res
}
