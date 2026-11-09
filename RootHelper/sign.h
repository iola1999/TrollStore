#ifndef TROLLSTORE_SIGN_H
#define TROLLSTORE_SIGN_H

#import <Foundation/Foundation.h>

NSDictionary *infoDictionaryForAppPath(NSString *appPath);
NSString *appIdForAppPath(NSString *appPath);
NSString *appMainExecutablePathForAppPath(NSString *appPath);
BOOL isMachoFile(NSString *filePath);
BOOL isSameFile(NSString *path1, NSString *path2);

void installLdid(NSString *ldidToCopyPath, NSString *ldidVersion);
BOOL isLdidInstalled(void);
NSString *getLdidPath(void);

int signAdhoc(NSString *filePath, NSDictionary *entitlements);
int signApp(NSString *appPath);

#endif
