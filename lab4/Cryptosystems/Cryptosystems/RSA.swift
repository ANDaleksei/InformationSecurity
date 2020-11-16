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
  if bitCount == 256 {
    p = BInt("49988642677360876696928568044969079570229858334285891638689744950998065293089")!
    q = BInt("16816601906811254867247487836331541113144937852038210642753538934794088763267")!
  } else if bitCount == 384 {
    p = BInt("2404276668318296312136549043580113969424075569531398791502068672698329576444619107720772480315593570702829737514879")!
    q = BInt("29374957098525184916600806643096955595486124981422824938974220720690688992873412803656237638087421442049538814142137")!
  } else if bitCount == 512 {
    p = BInt("8900543240482997754914162044025767982635627519343459756728976360080718086381430676688651765068519047576132957558436321163510739964410181269608508885633461")!
    q = BInt("10202766040255127271125425654523124798174533366051360568713040811498275114109338135715156609748318552691463701476718163519911834599980746685789117212304651")!
  } else if bitCount == 640 {
    p = BInt("1903097582272872100826436608155163716195173401060808183567597933277598202846449820318869946653819097066701999095602474165970828260387048259782119927120639746863878859092830154822354516847777241")!
    q = BInt("3263165692763434698327673448196094970168140049149631782500355796863394308965114251539931224096175772338549311921389343325012107868195407460543366201755409433607384868874590092484112101817196817")!
  } else if bitCount == 768 {
    p = BInt("656458951379012449504376196871943619440495180230601480383496996533431847735995965678743473323991335360130523047744619245016820865639206461421844592559605169138815693929893570104137477644568145357772579140509108788961325293277382573")!
    q = BInt("822534388440736576214516360507921703074463744100225107726104039145456365019467807003643158412021786060711124109306521082974949514316157866962823707203762950076443730322648158521844638521364166480929335941337293629186101779685296603")!
  } else if bitCount == 896 {
    p = BInt("224845574363477998477471901977114264543912240881106813129187461827453611250254539056242263966165006136525676841223571391496433214161151452728750563230346583429390143400987386618731016835777347863880433461762628018410175190056345960986830116090086962191167427429063172709")!
    q = BInt("407518303078467082049284322480077929744673416223221646856137166345223312300503045525476828721619068016556381853025555231098587805748962746935546446596452616216387963407893035196587340710385140421390799019332061346757110569718716929227197629915334544483311919075127976403")!
  } else if bitCount == 1024 {
    p = BInt("22708840355613233682109237396613520030457600103743090753960678125835729494635276449539726012210915088692852744768127458777702012615636183100056567231175226521269772169031062255316451294501451140769263398752910421943382527845505104361192936229744891825165633474459747881364562857504276929649718118947726167097")!
    q = BInt("152129620111385681928992466563457530085230531666063333603738019639822700510567337711283494812034791075115319282361392153047030172120917100476924380311058338487940651316262423194935791046668678430887295314421488433248856727364197525154183434175849723958516005131712433657333446268653134079256318517043422343427")!
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
