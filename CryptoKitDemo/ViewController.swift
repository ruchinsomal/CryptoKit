//
//  ViewController.swift
//  CryptoKitDemo
//
//  Created by Ruchin Somal on 20/10/19.
//  Copyright © 2019 Ruchin Somal. All rights reserved.
//

import UIKit
import CryptoKit

class ViewController: UIViewController {

    let inputString = "Hello, world!"
    var data: Data!
    let key = SymmetricKey(size: .bits256)
    let privateKey = Curve25519.Signing.PrivateKey()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        data = Data(inputString.utf8)
        SHA256Encrption()
        dataEncryption()
        creatingDigitalSignatures()
        keyAgreement()
    }

    private func SHA256Encrption() {
        let hashed = SHA256.hash(data: data)
        print("SHA 256 encrption " + hashed.description)
    }
    
    //MARK:- Encryption and Decryption Data using key
    private func dataEncryption() {
        if let sealedBox = try? ChaChaPoly.seal(data, using: key) {
            print("dataEncryption")
            print(sealedBox)
            dataDecryption(encryptedData: sealedBox.combined)
        }
    }
    
    private func dataDecryption(encryptedData: Data) {
        if let sealedBox = try? ChaChaPoly.SealedBox(combined: encryptedData),
            let decryptedData = try? ChaChaPoly.open(sealedBox, using: key) {
                print("dataDecryption")
            print(decryptedData.base64EncodedString())
            print(String(data: decryptedData, encoding: String.Encoding.utf8) ?? "")
        } else {
            print("error")
        }
    }
    
    //MARK:- Creating and Validating Digital Signatures
    private func creatingDigitalSignatures() {
        if let signature = try? privateKey.signature(for: data) {
            print(signature)
            validatingDigitalSignatures(signature: signature)
        }
    }
    
    private func validatingDigitalSignatures(signature: Data) {
        let publicKey = privateKey.publicKey
//        let publicKeyData = publicKey.rawRepresentation
        if publicKey.isValidSignature(signature, for: data) {
            print("The signature is valid")
        } else {
            print("The signature is invalid")
        }
    }
    
    //MARK:- Performing Key Agreement
    private func keyAgreement() {
        let privateKeyA = P521.KeyAgreement.PrivateKey()
        let publicKeyA = privateKeyA.publicKey

        let privateKeyB = P521.KeyAgreement.PrivateKey()
        let publicKeyB = privateKeyB.publicKey
        
        let sharedSecretA = try? privateKeyA.sharedSecretFromKeyAgreement(with: publicKeyB)
        let symmetricKeyA = sharedSecretA?.hkdfDerivedSymmetricKey(using: SHA256.self, salt: data, sharedInfo: Data(), outputByteCount: 32)
        
        let sharedSecretB = try? privateKeyB.sharedSecretFromKeyAgreement(with: publicKeyA)
        let symmetricKeyB = sharedSecretB?.hkdfDerivedSymmetricKey(using: SHA256.self, salt: data, sharedInfo: Data(), outputByteCount: 32)
        
        if symmetricKeyA == symmetricKeyB {
            print("User A and User B's symmetric keys are equal")
        } else {
            print("User A and User B's symmetric keys are unequal")
        }
    }
}

