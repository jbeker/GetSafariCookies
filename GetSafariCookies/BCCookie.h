#import <Foundation/Foundation.h>

@interface BCCookie : NSObject
@property (nonatomic, copy) NSString *domain;
@property (nonatomic, copy) NSString *path;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy) NSString *value;
@property (nonatomic) long expiresUnix;
@property (nonatomic) BOOL secure;
@property (nonatomic) BOOL httpOnly;

- (NSString *)netscapeLine;
@end
