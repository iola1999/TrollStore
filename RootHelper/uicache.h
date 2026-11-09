#import <Foundation/Foundation.h>
#include <stdbool.h>

extern void fixPermissionsOfAppBundle(NSString *appBundlePath);
extern bool registerPath(NSString *path, BOOL unregister, BOOL forceSystem);
extern int ensureTrollStoreInstalled(void);
extern void listInstalledApps(void);
