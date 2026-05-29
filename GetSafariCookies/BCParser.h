#import <Foundation/Foundation.h>
@class BCCookie;

@interface BCParser : NSObject
+ (NSArray<BCCookie *> *)parseData:(NSData *)data error:(NSError **)error;
@end
