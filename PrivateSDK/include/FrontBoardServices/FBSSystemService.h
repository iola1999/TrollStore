#ifndef FBSSYSTEMSERVICE_H
#define FBSSYSTEMSERVICE_H

#import <Foundation/Foundation.h>

@interface FBSSystemService : NSObject
+ (instancetype)sharedService;
- (void)reboot;
- (void)shutdown;
@end

#endif
