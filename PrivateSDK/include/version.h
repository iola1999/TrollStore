#ifndef VERSION_H
#define VERSION_H

#ifndef kCFCoreFoundationVersionNumber_iOS_15_0
#define kCFCoreFoundationVersionNumber_iOS_15_0 1854.0
#endif

#define IS_IOS_OR_NEWER(version) (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_##version)

#endif
