/********* KeyAcess.m Cordova Plugin Implementation *******/
#import "KeyAccess.h"
#import "NSData+Base64.h"
#define SERVICE_NAME @"keyData"

#include <iomanip>
#include "pem.h"
#include "engine.h"
#include <sstream>
#include "bio.h"
#include "rsa.h"

@implementation KeyAccess

#pragma mark- callback methods

- (void)deleteMethod:(CDVInvokedUrlCommand*)command
{
    keychain  =[[Keychain alloc] initWithService:SERVICE_NAME withGroup:nil];
    CDVPluginResult* pluginResult = nil;
     NSString *keyForVal=@"VPKey";
    
    if (keyForVal != nil && [keyForVal length] > 0) {
        
        NSString *msg=[self removeData:keyForVal];
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:msg];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}
#pragma mark - generate private public key
- (void)getPublicKey:(CDVInvokedUrlCommand*)command
{   keychain  =[[Keychain alloc] initWithService:SERVICE_NAME withGroup:nil];
    CDVPluginResult* pluginResult = nil;
    
    NSString *publicKey =[self generateKeys];
    NSLog(@"publicKey is %@",publicKey);
    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:publicKey];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

#pragma mark- signature
- (void)geneSigning:(CDVInvokedUrlCommand*)command
{
    keychain  =[[Keychain alloc] initWithService:SERVICE_NAME withGroup:nil];
    CDVPluginResult* pluginResult = nil;
    NSString* strToenc = [command.arguments objectAtIndex:0];
    NSString *keyForSign=[self fetchData:@"VPKey"];
    NSLog(@"keySign nerw log %@",keyForSign);
    NSLog(@"strToenc nerw log %@",strToenc);
    if ([keyForSign isEqualToString:@"Private key was not generated"]) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:keyForSign];
    }else{
       
        NSString *string = [self signHeader:strToenc withPrivateKey:keyForSign];
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:string];
    }
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

#pragma mark - keyChain methods
-(NSString *)storeData:(NSString *)keyForVal data:(NSString *)storeVal{
    NSString *key =keyForVal;
    NSString *errorMsg=@"Failed to Generate Keys";
    NSString *successMsg=@"Successfully store key";
    NSData * value = [storeVal dataUsingEncoding:NSUTF8StringEncoding];
    
    if([keychain insert:key :value])
    {
        return successMsg;
    }
    else{
        return  errorMsg;
    }
}

-(NSString *)fetchData :(NSString *)keyForVal{
    NSString *key= keyForVal;
    NSString *errorMsg=@"Private key was not generated";
    NSData * data =[keychain find:key];
    NSString *fetchString;
    if(data == nil)
    {
        return errorMsg;
    }
    else
    {
        fetchString=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        return fetchString;
    }
    
}

-(NSString *)removeData :(NSString *)keyForVal{
    NSString *key =keyForVal;
    NSString *success= @"Successfully key deleted";
    NSString *errorMsg= @"Fail to delete key";
    if([keychain remove:key])
    {
        return success;
    }
    else
    {
        return errorMsg;
    }
}

#pragma mark - generate public private key



- (NSString *)generateKeys
{
    error = [[BDError alloc] init];
    
    
    RSACryptor = [[BDRSACryptor alloc] init];
    
    RSAKeyPair = [RSACryptor generateKeyPairWithKeyIdentifier:@"keyChain.com.da"  error:error];
    NSString *publicKey= RSAKeyPair.publicKey;
    NSString *msg=[self storeData:@"VPKey" data:RSAKeyPair.privateKey];
    if ([msg isEqualToString:@"Failed to Generate Keys"]) {
        return msg;
    }else{
        
        return publicKey;
    }
}

 - (NSString*) signHeader:(NSString*) pTextString withPrivateKey: (NSString *) privateKey {
 
 
   BDError *error = [[BDError alloc] init];
   BDRSACryptor *RSACryptor = [[BDRSACryptor alloc] init];
 
 
   [RSACryptor setPrivateKey:privateKey tag:[RSACryptor privateKeyIdentifier] error:error];
 
   NSMutableDictionary *keyQueryDictionary = [RSACryptor keyQueryDictionary:[RSACryptor privateKeyIdentifier]];
   [keyQueryDictionary setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
 
 
   SecKeyRef privateKey1 = [RSACryptor keyRefWithTag:[RSACryptor privateKeyIdentifier]
   error:error];
 
   NSData *plainData = [pTextString dataUsingEncoding:NSUTF8StringEncoding];
 
   size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey1);
   uint8_t* signedHashBytes = (uint8_t*)malloc(signedHashBytesSize);
   memset(signedHashBytes, 0x0, signedHashBytesSize);
 
   size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
   uint8_t* hashBytes = (uint8_t*)malloc(hashBytesSize);
   if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
   return nil;
 }
 
   SecKeyRawSign(privateKey1,
                 kSecPaddingPKCS1SHA256,
                 hashBytes,
                 hashBytesSize,
                 signedHashBytes,
                 &signedHashBytesSize);
 
  NSData* signedHash = [NSData dataWithBytes:signedHashBytes
  length:(NSUInteger)signedHashBytesSize];
  NSString *signedString = [signedHash base64EncodedString];
  
 
      if (hashBytes)
      free(hashBytes);
      if (signedHashBytes)
      free(signedHashBytes);
 
      return signedString;
 
 }
 



@end
