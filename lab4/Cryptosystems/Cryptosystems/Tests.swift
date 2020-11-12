//
//  Tests.swift
//  Cryptosystems
//
//  Created by Oleksii Andriushchenko on 12.11.2020.
//

import Foundation
import BigNumber

func testMillerRabinTest() {
  // primes
  assert(checkIsPrime(number: BInt("9223372036854775643")!))
  assert(checkIsPrime(number: BInt("9223372036854775783")!))
  assert(checkIsPrime(number: BInt("10888869450418352160768000001")!))
  assert(checkIsPrime(number: BInt("263130836933693530167218012159999999")!))
  assert(checkIsPrime(number: BInt("8683317618811886495518194401279999999")!))
  // not primes
  assert(!checkIsPrime(number: BInt("473820483729301")!))
  assert(!checkIsPrime(number: BInt("94039283456473848373")!))
  assert(!checkIsPrime(number: BInt("1283049374098339402728391")!))
  assert(!checkIsPrime(number: BInt("409399877584938292018302046273")!))
  assert(!checkIsPrime(number: BInt("48573949372648576960584725341828997")!))
}
