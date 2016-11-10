//
//  KeyAcess.h
//  keyDemoProj
//
//  Created by Hitesh Rasal on 19/10/16.
//
//

#import <Cordova/CDV.h>
#import "Keychain.h"
#import "BDRSACryptor.h"
#import "BDRSACryptorKeyPair.h"
#import "BDError.h"
#import "BDLog.h"
#import <CommonCrypto/CommonDigest.h>

@interface KeyAccess : CDVPlugin {
    Keychain * keychain;
    BDRSACryptor *RSACryptor;
    BDError *error;
    BDRSACryptorKeyPair *RSAKeyPair;
}

- (void)deleteMethod:(CDVInvokedUrlCommand*)command;
- (void)getPublicKey:(CDVInvokedUrlCommand*)command;
- (void)geneSigning:(CDVInvokedUrlCommand*)command;
@end