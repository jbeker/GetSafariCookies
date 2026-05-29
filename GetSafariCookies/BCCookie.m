#import "BCCookie.h"

@implementation BCCookie
- (NSString *)netscapeLine {
    NSString *domainField = self.httpOnly
        ? [@"#HttpOnly_" stringByAppendingString:self.domain]
        : self.domain;
    NSString *includeSub = [self.domain hasPrefix:@"."] ? @"TRUE" : @"FALSE";
    NSString *secureField = self.secure ? @"TRUE" : @"FALSE";
    return [NSString stringWithFormat:@"%@\t%@\t%@\t%@\t%ld\t%@\t%@\n",
            domainField, includeSub, self.path, secureField,
            self.expiresUnix, self.name, self.value];
}
@end
