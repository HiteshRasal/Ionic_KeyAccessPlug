//
//  Keychain.h
//  keyChainSec
//
//  Created by Hitesh Rasal on 10/10/16.
//  Copyright © 2016 Hitesh Rasal. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Keychain : NSObject{
    NSString * service;
    NSString * group;
}

-(id) initWithService:(NSString *) service_ withGroup:(NSString*)group_;

-(BOOL) insert:(NSString *)key : (NSData *)data;
-(BOOL) remove: (NSString*)key;
-(NSData*) find:(NSString*)key;

@end
