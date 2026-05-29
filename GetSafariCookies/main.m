//
//  main.m
//  GetSafariCookies
//

#import <Foundation/Foundation.h>
#import "BCParser.h"
#import "BCCookie.h"

static NSString *DefaultCookiePath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:
        @"Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"];
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *path = (argc > 1)
            ? [NSString stringWithUTF8String:argv[1]]
            : DefaultCookiePath();

        NSError *err = nil;
        NSData *data = [NSData dataWithContentsOfFile:path options:0 error:&err];
        if (!data) {
            fprintf(stderr, "getsafaricookies: cannot read Safari cookies at %s\n",
                    path.UTF8String);
            fprintf(stderr, "  %s\n", err.localizedDescription.UTF8String);
            fprintf(stderr, "  Grant Full Disk Access to your terminal in System Settings >\n"
                            "  Privacy & Security > Full Disk Access, then retry.\n");
            return 1;
        }

        NSArray<BCCookie *> *cookies = [BCParser parseData:data error:&err];
        if (!cookies) {
            fprintf(stderr, "getsafaricookies: failed to parse cookies: %s\n",
                    err.localizedDescription.UTF8String);
            return 1;
        }

        for (BCCookie *cookie in cookies) {
            fputs(cookie.netscapeLine.UTF8String, stdout);
        }
    }
    return 0;
}
