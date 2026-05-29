#import "BCParser.h"
#import "BCCookie.h"

static NSString * const kBCParserErrorDomain = @"BCParserErrorDomain";
static const double kMacEpochOffset = 978307200.0;

static NSError *bcError(NSString *msg) {
    return [NSError errorWithDomain:kBCParserErrorDomain code:1
                          userInfo:@{NSLocalizedDescriptionKey: msg}];
}

static BOOL readBE32(const uint8_t *b, NSUInteger len, NSUInteger off, uint32_t *out) {
    if (off + 4 > len) return NO;
    *out = ((uint32_t)b[off] << 24) | ((uint32_t)b[off+1] << 16) |
           ((uint32_t)b[off+2] << 8) | (uint32_t)b[off+3];
    return YES;
}

static BOOL readLE32(const uint8_t *b, NSUInteger len, NSUInteger off, uint32_t *out) {
    if (off + 4 > len) return NO;
    *out = (uint32_t)b[off] | ((uint32_t)b[off+1] << 8) |
           ((uint32_t)b[off+2] << 16) | ((uint32_t)b[off+3] << 24);
    return YES;
}

static BOOL readLEDouble(const uint8_t *b, NSUInteger len, NSUInteger off, double *out) {
    if (off + 8 > len) return NO;
    uint64_t bits = 0;
    for (int i = 0; i < 8; i++) bits |= ((uint64_t)b[off+i] << (8 * i));
    memcpy(out, &bits, sizeof(double));
    return YES;
}

static NSString *readCString(const uint8_t *b, NSUInteger len, NSUInteger off) {
    if (off >= len) return nil;
    NSUInteger end = off;
    while (end < len && b[end] != 0) end++;
    if (end >= len) return nil;  // no NUL terminator within buffer
    return [[NSString alloc] initWithBytes:b + off length:end - off
                                  encoding:NSUTF8StringEncoding];
}

@implementation BCParser

+ (BCCookie *)parseCookieAt:(NSUInteger)cs bytes:(const uint8_t *)b
                   totalLen:(NSUInteger)len error:(NSError **)error {
    uint32_t size = 0, flags = 0, dOff = 0, nOff = 0, pOff = 0, vOff = 0;
    double expiry = 0;
    if (!readLE32(b, len, cs + 0, &size) || cs + size > len ||
        !readLE32(b, len, cs + 8, &flags) ||
        !readLE32(b, len, cs + 16, &dOff) || !readLE32(b, len, cs + 20, &nOff) ||
        !readLE32(b, len, cs + 24, &pOff) || !readLE32(b, len, cs + 28, &vOff) ||
        !readLEDouble(b, len, cs + 40, &expiry)) {
        if (error) *error = bcError(@"truncated cookie record");
        return nil;
    }
    NSString *domain = readCString(b, len, cs + dOff);
    NSString *name   = readCString(b, len, cs + nOff);
    NSString *path   = readCString(b, len, cs + pOff);
    NSString *value  = readCString(b, len, cs + vOff);
    if (!domain || !name || !path || !value) {
        if (error) *error = bcError(@"unreadable cookie strings");
        return nil;
    }
    BCCookie *c = [BCCookie new];
    c.domain = domain; c.name = name; c.path = path; c.value = value;
    c.secure = (flags & 0x1) != 0;
    c.httpOnly = (flags & 0x4) != 0;
    c.expiresUnix = (long)(expiry + kMacEpochOffset);
    return c;
}

+ (BOOL)parsePageAt:(NSUInteger)pageStart bytes:(const uint8_t *)b
           totalLen:(NSUInteger)len into:(NSMutableArray *)result
              error:(NSError **)error {
    uint32_t numCookies = 0;
    if (!readLE32(b, len, pageStart + 4, &numCookies)) {
        if (error) *error = bcError(@"truncated page header");
        return NO;
    }
    NSUInteger o = pageStart + 8;
    for (uint32_t i = 0; i < numCookies; i++) {
        uint32_t cookieOff = 0;
        if (!readLE32(b, len, o, &cookieOff)) {
            if (error) *error = bcError(@"truncated cookie offset table");
            return NO;
        }
        BCCookie *c = [self parseCookieAt:pageStart + cookieOff bytes:b
                                 totalLen:len error:error];
        if (!c) return NO;
        [result addObject:c];
        o += 4;
    }
    return YES;
}

+ (NSArray<BCCookie *> *)parseData:(NSData *)data error:(NSError **)error {
    const uint8_t *b = data.bytes;
    NSUInteger len = data.length;
    if (len < 8 || memcmp(b, "cook", 4) != 0) {
        if (error) *error = bcError(@"not a binarycookies file (bad magic)");
        return nil;
    }
    uint32_t numPages = 0;
    if (!readBE32(b, len, 4, &numPages)) {
        if (error) *error = bcError(@"truncated page count");
        return nil;
    }
    NSMutableArray<NSNumber *> *pageSizes = [NSMutableArray array];
    NSUInteger off = 8;
    for (uint32_t i = 0; i < numPages; i++) {
        uint32_t ps = 0;
        if (!readBE32(b, len, off, &ps)) {
            if (error) *error = bcError(@"truncated page size table");
            return nil;
        }
        [pageSizes addObject:@(ps)];
        off += 4;
    }
    NSMutableArray<BCCookie *> *result = [NSMutableArray array];
    NSUInteger pageStart = off;
    for (uint32_t i = 0; i < numPages; i++) {
        uint32_t ps = pageSizes[i].unsignedIntValue;
        if (pageStart + ps > len) {
            if (error) *error = bcError(@"page extends past end of file");
            return nil;
        }
        if (![self parsePageAt:pageStart bytes:b totalLen:len
                          into:result error:error]) {
            return nil;
        }
        pageStart += ps;
    }
    return result;
}

@end
