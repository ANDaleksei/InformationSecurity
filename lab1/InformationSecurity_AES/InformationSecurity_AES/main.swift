//
//  main.swift
//  InformationSecurity_AES
//
//  Created by Oleksii Andriushchenko on 28.09.2020.
//

import Foundation

testAes128()
testAes192()
testAes256()
print("Aes tests succeeded")
testKalynaConfig1Encryption()
testKalynaConfig1Decryption()
testKalynaConfig2Encryption()
testKalynaConfig2Decryption()
testKalynaConfig3Encryption()
testKalynaConfig3Decryption()
testKalynaConfig4Encryption()
testKalynaConfig4Decryption()
testKalynaConfig5Encryption()
testKalynaConfig5Decryption()
print("Kalyna tests succeeded")
checkPerformance()
