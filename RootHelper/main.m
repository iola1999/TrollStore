#import <stdio.h>
#import "unarchive.h"
#import <Foundation/Foundation.h>
#import "uicache.h"
#import <sys/stat.h>
#import <dlfcn.h>
#import <spawn.h>
#import <objc/runtime.h>
#import <TSUtil.h>
#import <sys/utsname.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import "devmode.h"
#import "jit.h"
#import "sign.h"
#include <CommonCrypto/CommonDigest.h>
#include <notify.h>
#include <unistd.h>

#import <SpringBoardServices/SpringBoardServices.h>
#import <FrontBoardServices/FBSSystemService.h>
#import <Security/Security.h>
#import <libroot.h>

#ifdef EMBEDDED_ROOT_HELPER
#define MAIN_NAME rootHelperMain
#else
#define MAIN_NAME main
#endif

void cleanRestrictions(void);

extern mach_msg_return_t SBReloadIconForIdentifier(mach_port_t machport, const char* identifier);
@interface SBSHomeScreenService : NSObject
- (void)reloadIcons;
@end
extern NSString* BKSActivateForEventOptionTypeBackgroundContentFetching;
extern NSString* BKSOpenApplicationOptionKeyActivateForEvent;

extern void BKSTerminateApplicationForReasonAndReportWithDescription(NSString *bundleID, int reasonID, bool report, NSString *description);

#define kCFPreferencesNoContainer CFSTR("kCFPreferencesNoContainer")

typedef CFPropertyListRef (*_CFPreferencesCopyValueWithContainerType)(CFStringRef key, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
typedef void (*_CFPreferencesSetValueWithContainerType)(CFStringRef key, CFPropertyListRef value, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
typedef Boolean (*_CFPreferencesSynchronizeWithContainerType)(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
typedef CFArrayRef (*_CFPreferencesCopyKeyListWithContainerType)(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
typedef CFDictionaryRef (*_CFPreferencesCopyMultipleWithContainerType)(CFArrayRef keysToFetch, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);

BOOL _installPersistenceHelper(LSApplicationProxy* appProxy, NSString* sourcePersistenceHelper, NSString* sourceRootHelper);

NSArray<LSApplicationProxy*>* applicationsWithGroupId(NSString* groupId)
{
	LSEnumerator* enumerator = [LSEnumerator enumeratorForApplicationProxiesWithOptions:0];
	enumerator.predicate = [NSPredicate predicateWithFormat:@"groupContainerURLs[%@] != nil", groupId];
	return enumerator.allObjects;
}

NSSet<NSString*>* systemURLSchemes(void)
{
	LSEnumerator* enumerator = [LSEnumerator enumeratorForApplicationProxiesWithOptions:0];

	NSMutableSet* systemURLSchemesSet = [NSMutableSet new];
	LSApplicationProxy* proxy;
	while(proxy = [enumerator nextObject])
	{
		if(isRemovableSystemApp(proxy.bundleIdentifier) || ![proxy.bundleURL.path hasPrefix:@"/private/var/containers"])
		{
			for(NSString* claimedURLScheme in proxy.claimedURLSchemes)
			{
				if([claimedURLScheme isKindOfClass:NSString.class])
				{
					[systemURLSchemesSet addObject:claimedURLScheme.lowercaseString];
				}
			}
		}
	}

	return systemURLSchemesSet.copy;
}

NSSet<NSString*>* immutableAppBundleIdentifiers(void)
{
	NSMutableSet* systemAppIdentifiers = [NSMutableSet new];

	LSEnumerator* enumerator = [LSEnumerator enumeratorForApplicationProxiesWithOptions:0];
	LSApplicationProxy* appProxy;
	while(appProxy = [enumerator nextObject])
	{
		if(appProxy.installed)
		{
			if(![appProxy.bundleURL.path hasPrefix:@"/private/var/containers"])
			{
				[systemAppIdentifiers addObject:appProxy.bundleIdentifier.lowercaseString];
			}
		}
	}

	return systemAppIdentifiers.copy;
}

NSString* appPathForAppId(NSString* appId)
{
	if(!appId) return nil;
	for(NSString* appPath in trollStoreInstalledAppBundlePaths())
	{
		if([appIdForAppPath(appPath) isEqualToString:appId])
		{
			return appPath;
		}
	}
	LSApplicationProxy *proxy = [LSApplicationProxy applicationProxyForIdentifier:appId];
	if (proxy.bundleURL.path.length > 0 && [proxy.bundleURL.path hasPrefix:@"/private/var/containers/Bundle/Application/"]) {
		return proxy.bundleURL.path;
	}
	return nil;
}

NSString* findAppNameInBundlePath(NSString* bundlePath)
{
	NSArray* bundleItems = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundlePath error:nil];
	for(NSString* bundleItem in bundleItems)
	{
		if([bundleItem.pathExtension isEqualToString:@"app"])
		{
			return bundleItem;
		}
	}
	return nil;
}

NSString* findAppPathInBundlePath(NSString* bundlePath)
{
	NSString* appName = findAppNameInBundlePath(bundlePath);
	if(!appName) return nil;
	return [bundlePath stringByAppendingPathComponent:appName];
}

NSURL* findAppURLInBundleURL(NSURL* bundleURL)
{
	NSString* appName = findAppNameInBundlePath(bundleURL.path);
	if(!appName) return nil;
	return [bundleURL URLByAppendingPathComponent:appName];
}

NSArray* TSURLScheme(void)
{
	return @[
		@{
			@"CFBundleURLName" : @"com.apple.Magnifier",
			@"CFBundleURLSchemes" : @[
				@"apple-magnifier"
			]
		}
	];
}

BOOL getTSURLSchemeState(NSString* customAppPath)
{
	NSString* pathToUse = customAppPath ?: trollStoreAppPath();

	NSDictionary* trollStoreInfoDict = infoDictionaryForAppPath(pathToUse);
	return (BOOL)trollStoreInfoDict[@"CFBundleURLTypes"];
}

void setTSURLSchemeState(BOOL newState, NSString* customAppPath)
{
	NSString* tsAppPath = trollStoreAppPath();
	NSString* pathToUse = customAppPath ?: tsAppPath;
	if(newState != getTSURLSchemeState(pathToUse))
	{
		NSDictionary* trollStoreInfoDict = infoDictionaryForAppPath(pathToUse);
		NSMutableDictionary* trollStoreInfoDictM = trollStoreInfoDict.mutableCopy;
		if(newState)
		{
			trollStoreInfoDictM[@"CFBundleURLTypes"] = TSURLScheme();
		}
		else
		{
			[trollStoreInfoDictM removeObjectForKey:@"CFBundleURLTypes"];
		}
		NSString* outPath = [pathToUse stringByAppendingPathComponent:@"Info.plist"];
		[trollStoreInfoDictM.copy writeToURL:[NSURL fileURLWithPath:outPath] error:nil];
	}
}

void applyPatchesToInfoDictionary(NSString* appPath)
{
	NSURL* appURL = [NSURL fileURLWithPath:appPath];
	NSURL* infoPlistURL = [appURL URLByAppendingPathComponent:@"Info.plist"];
	NSMutableDictionary* infoDictM = [[NSDictionary dictionaryWithContentsOfURL:infoPlistURL error:nil] mutableCopy];
	if(!infoDictM) return;

	// Enable Notifications
	infoDictM[@"SBAppUsesLocalNotifications"] = @1;

	// Remove system claimed URL schemes if existant
	NSSet* appleSchemes = systemURLSchemes();
	NSArray* CFBundleURLTypes = infoDictM[@"CFBundleURLTypes"];
	if([CFBundleURLTypes isKindOfClass:[NSArray class]])
	{
		NSMutableArray* CFBundleURLTypesM = [NSMutableArray new];

		for(NSDictionary* URLType in CFBundleURLTypes)
		{
			if(![URLType isKindOfClass:[NSDictionary class]]) continue;

			NSMutableDictionary* modifiedURLType = URLType.mutableCopy;
			NSArray* URLSchemes = URLType[@"CFBundleURLSchemes"];
			if(URLSchemes)
			{
				NSMutableSet* URLSchemesSet = [NSMutableSet setWithArray:URLSchemes];
				for(NSString* existingURLScheme in [URLSchemesSet copy])
				{
					if(![existingURLScheme isKindOfClass:[NSString class]])
					{
						[URLSchemesSet removeObject:existingURLScheme];
						continue;
					}

					if([appleSchemes containsObject:existingURLScheme.lowercaseString])
					{
						[URLSchemesSet removeObject:existingURLScheme];
					}
				}
				modifiedURLType[@"CFBundleURLSchemes"] = [URLSchemesSet allObjects];
			}
			[CFBundleURLTypesM addObject:modifiedURLType.copy];
		}

		infoDictM[@"CFBundleURLTypes"] = CFBundleURLTypesM.copy;
	}

	[infoDictM writeToURL:infoPlistURL error:nil];
}

// 170: failed to create container for app bundle
// 171: a non trollstore app with the same identifier is already installled
// 172: no info.plist found in app
// 173: app is not signed and cannot be signed because ldid not installed or didn't work
// 174: 
// 180: tried to sign app where the main binary is encrypted
// 184: tried to sign app where an additional binary is encrypted

int installApp(NSString* appPackagePath, BOOL sign, BOOL force, BOOL isTSUpdate, BOOL useInstalldMethod, BOOL skipUICache)
{
	NSLog(@"[installApp force = %d]", force);

	NSString* appPayloadPath = [appPackagePath stringByAppendingPathComponent:@"Payload"];

	NSString* appBundleToInstallPath = findAppPathInBundlePath(appPayloadPath);
	if(!appBundleToInstallPath) return 167;

	NSString* appId = appIdForAppPath(appBundleToInstallPath);
	if(!appId) return 176;

	if(([appId.lowercaseString isEqualToString:@"com.opa334.trollstore"] && !isTSUpdate) || [immutableAppBundleIdentifiers() containsObject:appId.lowercaseString])
	{
		return 179;
	}

	if(!infoDictionaryForAppPath(appBundleToInstallPath)) return 172;

	if(!isTSUpdate)
	{
		applyPatchesToInfoDictionary(appBundleToInstallPath);
	}

	BOOL requiresDevMode = NO;
	BOOL hasAdditionalEncryptedBinaries = NO;

	if(sign)
	{
		int signRet = signApp(appBundleToInstallPath);
		// 182: app requires developer mode; non-fatal
		// 184: app has additional encrypted binaries; non-fatal
		if(signRet != 0) {
			if (signRet == 182) {
				requiresDevMode = YES;
			} else if (signRet == 184) {
				hasAdditionalEncryptedBinaries = YES;
			} else {
				return signRet;
			}
		};
	}

	MCMAppContainer* appContainer = [MCMAppContainer containerWithIdentifier:appId createIfNecessary:NO existed:nil error:nil];
	if(appContainer)
	{
		// App update
		// Replace existing bundle with new version

		// Check if the existing app bundle is empty
		NSURL* bundleContainerURL = appContainer.url;
		NSURL* appBundleURL = findAppURLInBundleURL(bundleContainerURL);

		// Make sure the installed app is a TrollStore app or the container is empty (or the force flag is set)
		NSURL* trollStoreMarkURL = [bundleContainerURL URLByAppendingPathComponent:TS_ACTIVE_MARKER];
		if(appBundleURL && ![trollStoreMarkURL checkResourceIsReachableAndReturnError:nil] && !force)
		{
			NSLog(@"[installApp] already installed and not a TrollStore app... bailing out");
			return 171;
		}
		else if (appBundleURL) {
			// When overwriting an app that has been installed with a different TrollStore flavor, make sure to remove the marker of said flavor
			NSURL *otherMarkerURL = [bundleContainerURL URLByAppendingPathComponent:TS_INACTIVE_MARKER];
			if ([otherMarkerURL checkResourceIsReachableAndReturnError:nil]) {
				[[NSFileManager defaultManager] removeItemAtURL:otherMarkerURL error:nil];
			}
		}

		// Terminate app if it's still running
		if(!isTSUpdate)
		{
			BKSTerminateApplicationForReasonAndReportWithDescription(appId, 5, false, @"TrollStore - App updated");
		}

		NSLog(@"[installApp] replacing existing app with new version");

		// Delete existing .app directory if it exists
		if(appBundleURL)
		{
			[[NSFileManager defaultManager] removeItemAtURL:appBundleURL error:nil];
		}

		NSString* newAppBundlePath = [bundleContainerURL.path stringByAppendingPathComponent:appBundleToInstallPath.lastPathComponent];
		NSLog(@"[installApp] new app path: %@", newAppBundlePath);

		// Install new version into existing app bundle
		NSError* copyError;
		BOOL suc = [[NSFileManager defaultManager] copyItemAtPath:appBundleToInstallPath toPath:newAppBundlePath error:&copyError];
		if(!suc)
		{
			NSLog(@"[installApp] Error copying new version during update: %@", copyError);
			return 178;
		}
	}
	else
	{
		// Initial app install
		BOOL systemMethodSuccessful = NO;
		if(useInstalldMethod)
		{
			// System method
			// Do initial placeholder installation using LSApplicationWorkspace
			NSLog(@"[installApp] doing placeholder installation using LSApplicationWorkspace");

			// The installApplication API (re)moves the app bundle, so in order to be able to later 
			// fall back to the custom method, we need to make a temporary copy just for using it on this API once
			// Yeah this sucks, but there is no better solution unfortunately
			NSError* tmpCopyError;
			NSString* lsAppPackageTmpCopy = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
			if(![[NSFileManager defaultManager] copyItemAtPath:appPackagePath toPath:lsAppPackageTmpCopy error:&tmpCopyError])
			{
				NSLog(@"failed to make temporary copy of app packge: %@", tmpCopyError);
				return 170;
			}

			NSError* installError;
			@try
			{
				systemMethodSuccessful = [[LSApplicationWorkspace defaultWorkspace] installApplication:[NSURL fileURLWithPath:lsAppPackageTmpCopy] withOptions:@{
					LSInstallTypeKey : @1,
					@"PackageType" : @"Placeholder"
				} error:&installError];
			}
			@catch(NSException* e)
			{
				NSLog(@"[installApp] encountered expection %@ while trying to do placeholder install", e);
				systemMethodSuccessful = NO;
			}

			if(!systemMethodSuccessful)
			{
				NSLog(@"[installApp] encountered error %@ while trying to do placeholder install", installError);
			}

			[[NSFileManager defaultManager] removeItemAtPath:lsAppPackageTmpCopy error:nil];
		}

		if(!systemMethodSuccessful)
		{
			// Custom method
			// Manually create app bundle via MCM apis and move app there
			NSLog(@"[installApp] doing custom installation using MCMAppContainer");

			NSError* mcmError;
			appContainer = [MCMAppContainer containerWithIdentifier:appId createIfNecessary:YES existed:nil error:&mcmError];

			if(!appContainer || mcmError)
			{
				NSLog(@"[installApp] failed to create app container for %@: %@", appId, mcmError);
				return 170;
			}
			else
			{
				NSLog(@"[installApp] created app container: %@", appContainer);
			}

			NSString* newAppBundlePath = [appContainer.url.path stringByAppendingPathComponent:appBundleToInstallPath.lastPathComponent];
			NSLog(@"[installApp] new app path: %@", newAppBundlePath);
			
			NSError* copyError;
			BOOL suc = [[NSFileManager defaultManager] copyItemAtPath:appBundleToInstallPath toPath:newAppBundlePath error:&copyError];
			if(!suc)
			{
				NSLog(@"[installApp] Failed to copy app bundle for app %@, error: %@", appId, copyError);
				return 178;
			}
		}
	}

	appContainer = [MCMAppContainer containerWithIdentifier:appId createIfNecessary:NO existed:nil error:nil];

	// Mark app as TrollStore app
	NSURL* trollStoreMarkURL = [appContainer.url URLByAppendingPathComponent:TS_ACTIVE_MARKER];
	if(![[NSFileManager defaultManager] fileExistsAtPath:trollStoreMarkURL.path])
	{
		NSError* creationError;
		NSData* emptyData = [NSData data];
		BOOL marked = [emptyData writeToURL:trollStoreMarkURL options:0 error:&creationError];
		if(!marked)
		{
			NSLog(@"[installApp] failed to mark %@ as TrollStore app by creating %@, error: %@", appId, trollStoreMarkURL.path, creationError);
			return 177;
		}
	}

	// At this point the (new version of the) app is installed but still needs to be registered
	// Also permissions need to be fixed
	NSURL* updatedAppURL = findAppURLInBundleURL(appContainer.url);
	fixPermissionsOfAppBundle(updatedAppURL.path);
	if (!skipUICache) {
		if (!registerPath(updatedAppURL.path, 0, !shouldRegisterAsUserByDefault())) {
			[[NSFileManager defaultManager] removeItemAtURL:appContainer.url error:nil];
			return 181;
		}
	}

	// Handle developer mode after installing and registering the app, to ensure that we
	// don't arm developer mode but then fail to install the app
	if (requiresDevMode) {
		BOOL alreadyEnabled = NO;
		if (armDeveloperMode(&alreadyEnabled)) {
			if (!alreadyEnabled) {
				NSLog(@"[installApp] app requires developer mode and we have successfully armed it");
				// non-fatal
				return 182;
			}
		} else {
			NSLog(@"[installApp] failed to arm developer mode");
			// fatal
			return 183;
		}
	}

	if (hasAdditionalEncryptedBinaries) {
		NSLog(@"[installApp] app has additional encrypted binaries");
		// non-fatal
		return 184;
	}

	return 0;
}

int uninstallApp(NSString* appPath, NSString* appId, BOOL useCustomMethod)
{
	BOOL deleteSuc = NO;
	if(!appId && appPath)
	{
		// Special case, something is wrong about this app
		// Most likely the Info.plist is missing
		// (Hopefully this never happens)
		deleteSuc = [[NSFileManager defaultManager] removeItemAtPath:[appPath stringByDeletingLastPathComponent] error:nil];
		registerPath(appPath, YES, YES);
		return 0;
	}

	if(appId)
	{
		LSApplicationProxy* appProxy = [LSApplicationProxy applicationProxyForIdentifier:appId];

		// delete data container
		if (appProxy.dataContainerURL) {
			[[NSFileManager defaultManager] removeItemAtURL:appProxy.dataContainerURL error:nil];
		}

		// delete group container paths
		[[appProxy groupContainerURLs] enumerateKeysAndObjectsUsingBlock:^(NSString* groupId, NSURL* groupURL, BOOL* stop)
		{
			// If another app still has this group, don't delete it
			NSArray<LSApplicationProxy*>* appsWithGroup = applicationsWithGroupId(groupId);
			if(appsWithGroup.count > 1)
			{
				NSLog(@"[uninstallApp] not deleting %@, appsWithGroup.count:%lu", groupURL, appsWithGroup.count);
				return;
			}

			NSLog(@"[uninstallApp] deleting %@", groupURL);
			[[NSFileManager defaultManager] removeItemAtURL:groupURL error:nil];
		}];

		// delete app plugin paths
		for(LSPlugInKitProxy* pluginProxy in appProxy.plugInKitPlugins)
		{
			NSURL* pluginURL = pluginProxy.dataContainerURL;
			if(pluginURL)
			{
				NSLog(@"[uninstallApp] deleting %@", pluginURL);
				[[NSFileManager defaultManager] removeItemAtURL:pluginURL error:nil];
			}
		}

		BOOL systemMethodSuccessful = NO;
		if(!useCustomMethod)
		{
			systemMethodSuccessful = [[LSApplicationWorkspace defaultWorkspace] uninstallApplication:appId withOptions:nil];
		}

		if(!systemMethodSuccessful)
		{
			deleteSuc = [[NSFileManager defaultManager] removeItemAtPath:[appPath stringByDeletingLastPathComponent] error:nil];
			registerPath(appPath, YES, YES);
		}
		else
		{
			deleteSuc = systemMethodSuccessful;
		}
	}

	if(deleteSuc)
	{
		cleanRestrictions();
		notify_post("com.apple.LaunchServices.ApplicationsChanged");
		notify_post("com.annibale.var_save");
		sync();
		return 0;
	}
	else
	{
		return 1;
	}
}

int uninstallAppByPath(NSString* appPath, BOOL useCustomMethod)
{
	if(!appPath) return 1;

	NSString* standardizedAppPath = appPath.stringByStandardizingPath;

	if(![standardizedAppPath hasPrefix:@"/var/containers/Bundle/Application/"] && standardizedAppPath.pathComponents.count == 5)
	{
		return 1;
	}

	NSString* appId = appIdForAppPath(standardizedAppPath);
	return uninstallApp(appPath, appId, useCustomMethod);
}

int uninstallAppById(NSString* appId, BOOL useCustomMethod)
{
	if(!appId) return 1;
	NSString* appPath = appPathForAppId(appId);
	if(!appPath) return 1;
	return uninstallApp(appPath, appId, useCustomMethod);
}

// 166: IPA does not exist or is not accessible
// 167: IPA does not appear to contain an app
// 180: IPA's main binary is encrypted
// 184: IPA contains additional encrypted binaries
int installIpa(NSString* ipaPath, BOOL force, BOOL useInstalldMethod, BOOL skipUICache)
{
	cleanRestrictions();

	BOOL isDir = NO;
	if(![[NSFileManager defaultManager] fileExistsAtPath:ipaPath isDirectory:&isDir]) return 166;

	BOOL suc = NO;
	NSString* tmpPackagePath = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
	
	suc = [[NSFileManager defaultManager] createDirectoryAtPath:tmpPackagePath withIntermediateDirectories:NO attributes:nil error:nil];
	if(!suc) return 1;

	if (isDir && [ipaPath.pathExtension.lowercaseString isEqualToString:@"app"]) {
		NSString *payloadDir = [tmpPackagePath stringByAppendingPathComponent:@"Payload"];
		[[NSFileManager defaultManager] createDirectoryAtPath:payloadDir withIntermediateDirectories:YES attributes:nil error:nil];
		NSString *dstApp = [payloadDir stringByAppendingPathComponent:ipaPath.lastPathComponent];
		if (![[NSFileManager defaultManager] copyItemAtPath:ipaPath toPath:dstApp error:nil]) {
			[[NSFileManager defaultManager] removeItemAtPath:tmpPackagePath error:nil];
			return 168;
		}
	} else {
		int extractRet = extract(ipaPath, tmpPackagePath);
		if(extractRet != 0)
		{
			[[NSFileManager defaultManager] removeItemAtPath:tmpPackagePath error:nil];
			return 168;
		}
	}

	int ret = installApp(tmpPackagePath, YES, force, NO, useInstalldMethod, skipUICache);
	
	[[NSFileManager defaultManager] removeItemAtPath:tmpPackagePath error:nil];

	return ret;
}

void uninstallAllApps(BOOL useCustomMethod)
{
	for(NSString* appPath in trollStoreInstalledAppBundlePaths())
	{
		uninstallAppById(appIdForAppPath(appPath), useCustomMethod);
	}
}

int uninstallTrollStore(BOOL unregister)
{
	NSString* trollStore = trollStorePath();
	if(![[NSFileManager defaultManager] fileExistsAtPath:trollStore]) return NO;

	if(unregister)
	{
		registerPath(trollStoreAppPath(), YES, YES);
	}

	return [[NSFileManager defaultManager] removeItemAtPath:trollStore error:nil];
}

int installTrollStore(NSString* pathToTar)
{
	_CFPreferencesSetValueWithContainerType _CFPreferencesSetValueWithContainer = (_CFPreferencesSetValueWithContainerType)dlsym(RTLD_DEFAULT, "_CFPreferencesSetValueWithContainer");
	_CFPreferencesSynchronizeWithContainerType _CFPreferencesSynchronizeWithContainer = (_CFPreferencesSynchronizeWithContainerType)dlsym(RTLD_DEFAULT, "_CFPreferencesSynchronizeWithContainer");
	_CFPreferencesSetValueWithContainer(CFSTR("SBShowNonDefaultSystemApps"), kCFBooleanTrue, CFSTR("com.apple.springboard"), CFSTR("mobile"), kCFPreferencesAnyHost, kCFPreferencesNoContainer);
	_CFPreferencesSynchronizeWithContainer(CFSTR("com.apple.springboard"), CFSTR("mobile"), kCFPreferencesAnyHost, kCFPreferencesNoContainer);

	if(![[NSFileManager defaultManager] fileExistsAtPath:pathToTar]) return 1;
	if(![pathToTar.pathExtension isEqualToString:@"tar"]) return 1;

	NSString* tmpPackagePath = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
	NSString* tmpPayloadPath = [tmpPackagePath stringByAppendingPathComponent:@"Payload"];
	BOOL suc = [[NSFileManager defaultManager] createDirectoryAtPath:tmpPayloadPath withIntermediateDirectories:YES attributes:nil error:nil];
	if(!suc) return 1;

	int extractRet = extract(pathToTar, tmpPayloadPath);
	if(extractRet != 0)
	{
		[[NSFileManager defaultManager] removeItemAtPath:tmpPackagePath error:nil];
		return 169;
	}

	NSString* tmpTrollStorePath = [tmpPayloadPath stringByAppendingPathComponent:@"TrollStore.app"];
	if(![[NSFileManager defaultManager] fileExistsAtPath:tmpTrollStorePath]) return 1;

	//if (@available(iOS 16, *)) {} else {
		// Transfer existing ldid installation if it exists
		// But only if the to-be-installed version of TrollStore is 1.5.0 or above
		// This is to make it possible to downgrade to older versions still

		NSString* toInstallInfoPlistPath = [tmpTrollStorePath stringByAppendingPathComponent:@"Info.plist"];
		if(![[NSFileManager defaultManager] fileExistsAtPath:toInstallInfoPlistPath]) return 1;

		NSDictionary* toInstallInfoDict = [NSDictionary dictionaryWithContentsOfFile:toInstallInfoPlistPath];
		NSString* toInstallVersion = toInstallInfoDict[@"CFBundleVersion"];

		NSComparisonResult result = [@"1.5.0" compare:toInstallVersion options:NSNumericSearch];
		if(result != NSOrderedDescending)
		{
			NSString* existingLdidPath = [trollStoreAppPath() stringByAppendingPathComponent:@"ldid"];
			NSString* existingLdidVersionPath = [trollStoreAppPath() stringByAppendingPathComponent:@"ldid.version"];
			if([[NSFileManager defaultManager] fileExistsAtPath:existingLdidPath])
			{
				NSString* tmpLdidPath = [tmpTrollStorePath stringByAppendingPathComponent:@"ldid"];
				if(![[NSFileManager defaultManager] fileExistsAtPath:tmpLdidPath])
				{
					[[NSFileManager defaultManager] copyItemAtPath:existingLdidPath toPath:tmpLdidPath error:nil];
				}
			}
			if([[NSFileManager defaultManager] fileExistsAtPath:existingLdidVersionPath])
			{
				NSString* tmpLdidVersionPath = [tmpTrollStorePath stringByAppendingPathComponent:@"ldid.version"];
				if(![[NSFileManager defaultManager] fileExistsAtPath:tmpLdidVersionPath])
				{
					[[NSFileManager defaultManager] copyItemAtPath:existingLdidVersionPath toPath:tmpLdidVersionPath error:nil];
				}
			}
		}
	//}

	// Merge existing URL scheme settings value
	if(!getTSURLSchemeState(nil))
	{
		setTSURLSchemeState(NO, tmpTrollStorePath);
	}

	// Update system app persistence helper if used
	LSApplicationProxy* persistenceHelperApp = findPersistenceHelperApp(PERSISTENCE_HELPER_TYPE_SYSTEM);
	if(persistenceHelperApp)
	{
		NSString* trollStorePersistenceHelper = [tmpTrollStorePath stringByAppendingPathComponent:@"PersistenceHelper"];
		NSString* trollStoreRootHelper = [tmpTrollStorePath stringByAppendingPathComponent:@"trollstorehelper"];
		_installPersistenceHelper(persistenceHelperApp, trollStorePersistenceHelper, trollStoreRootHelper);
	}

	int ret = installApp(tmpPackagePath, NO, YES, YES, YES, NO);
	NSLog(@"[installTrollStore] installApp => %d", ret);
	[[NSFileManager defaultManager] removeItemAtPath:tmpPackagePath error:nil];
	return ret;
}

void refreshAppRegistrations(BOOL system)
{
	registerPath(trollStoreAppPath(), NO, system);

	// the reason why there is even an option to register everything as user
	// is because it fixes an issue where app permissions would reset during an icon cache reload
	for(NSString* appPath in trollStoreInstalledAppBundlePaths())
	{
		registerPath(appPath, NO, system);
	}
}

BOOL _installPersistenceHelper(LSApplicationProxy* appProxy, NSString* sourcePersistenceHelper, NSString* sourceRootHelper)
{
	NSLog(@"_installPersistenceHelper(%@, %@, %@)", appProxy, sourcePersistenceHelper, sourceRootHelper);

	NSString* executablePath = appProxy.canonicalExecutablePath;
	NSString* bundlePath = appProxy.bundleURL.path;
	if(!executablePath)
	{
		NSBundle* appBundle = [NSBundle bundleWithPath:bundlePath];
		executablePath = [bundlePath stringByAppendingPathComponent:[appBundle objectForInfoDictionaryKey:@"CFBundleExecutable"]];
	}

	NSString* markPath = [bundlePath stringByAppendingPathComponent:@".TrollStorePersistenceHelper"];
	NSString* rootHelperPath = [bundlePath stringByAppendingPathComponent:@"trollstorehelper"];

	// remove existing persistence helper binary if exists
	if([[NSFileManager defaultManager] fileExistsAtPath:markPath] && [[NSFileManager defaultManager] fileExistsAtPath:executablePath])
	{
		[[NSFileManager defaultManager] removeItemAtPath:executablePath error:nil];
	}

	// remove existing root helper binary if exists
	if([[NSFileManager defaultManager] fileExistsAtPath:rootHelperPath])
	{
		[[NSFileManager defaultManager] removeItemAtPath:rootHelperPath error:nil];
	}

	// install new persistence helper binary
	if(![[NSFileManager defaultManager] copyItemAtPath:sourcePersistenceHelper toPath:executablePath error:nil])
	{
		return NO;
	}

	chmod(executablePath.fileSystemRepresentation, 0755);
	chown(executablePath.fileSystemRepresentation, 33, 33);

	NSError* error;
	if(![[NSFileManager defaultManager] copyItemAtPath:sourceRootHelper toPath:rootHelperPath error:&error])
	{
		NSLog(@"error copying root helper: %@", error);
	}

	chmod(rootHelperPath.fileSystemRepresentation, 0755);
	chown(rootHelperPath.fileSystemRepresentation, 0, 0);

	// mark system app as persistence helper
	if(![[NSFileManager defaultManager] fileExistsAtPath:markPath])
	{
		[[NSFileManager defaultManager] createFileAtPath:markPath contents:[NSData data] attributes:nil];
	}

	return YES;
}

void installPersistenceHelper(NSString* systemAppId, NSString *persistenceHelperBinary, NSString *rootHelperBinary)
{
	if(findPersistenceHelperApp(PERSISTENCE_HELPER_TYPE_ALL)) return;

	if (persistenceHelperBinary == nil) {
		persistenceHelperBinary = [trollStoreAppPath() stringByAppendingPathComponent:@"PersistenceHelper"];
	}
	if (rootHelperBinary == nil) {
		rootHelperBinary = [trollStoreAppPath() stringByAppendingPathComponent:@"trollstorehelper"];
	}
	LSApplicationProxy* appProxy = [LSApplicationProxy applicationProxyForIdentifier:systemAppId];
	if(!appProxy || ![appProxy.bundleType isEqualToString:@"System"]) return;

	NSString* executablePath = appProxy.canonicalExecutablePath;
	NSString* bundlePath = appProxy.bundleURL.path;
	NSString* backupPath = [bundlePath stringByAppendingPathComponent:[[executablePath lastPathComponent] stringByAppendingString:@"_TROLLSTORE_BACKUP"]];

	if([[NSFileManager defaultManager] fileExistsAtPath:backupPath]) return;

	if(![[NSFileManager defaultManager] moveItemAtPath:executablePath toPath:backupPath error:nil]) return;

	if(!_installPersistenceHelper(appProxy, persistenceHelperBinary, rootHelperBinary))
	{
		[[NSFileManager defaultManager] moveItemAtPath:backupPath toPath:executablePath error:nil];
		return;
	}

	BKSTerminateApplicationForReasonAndReportWithDescription(systemAppId, 5, false, @"TrollStore - Reload persistence helper");
}

void unregisterUserPersistenceHelper()
{
	LSApplicationProxy* userAppProxy = findPersistenceHelperApp(PERSISTENCE_HELPER_TYPE_USER);
	if(userAppProxy)
	{
		NSString* markPath = [userAppProxy.bundleURL.path stringByAppendingPathComponent:@".TrollStorePersistenceHelper"];
		[[NSFileManager defaultManager] removeItemAtPath:markPath error:nil];
	}
}

void uninstallPersistenceHelper(void)
{
	LSApplicationProxy* systemAppProxy = findPersistenceHelperApp(PERSISTENCE_HELPER_TYPE_SYSTEM);
	if(systemAppProxy)
	{
		NSString* executablePath = systemAppProxy.canonicalExecutablePath;
		NSString* bundlePath = systemAppProxy.bundleURL.path;
		NSString* backupPath = [bundlePath stringByAppendingPathComponent:[[executablePath lastPathComponent] stringByAppendingString:@"_TROLLSTORE_BACKUP"]];
		if(![[NSFileManager defaultManager] fileExistsAtPath:backupPath]) return;

		NSString* helperPath = [bundlePath stringByAppendingPathComponent:@"trollstorehelper"];
		NSString* markPath = [bundlePath stringByAppendingPathComponent:@".TrollStorePersistenceHelper"];

		[[NSFileManager defaultManager] removeItemAtPath:executablePath error:nil];
		[[NSFileManager defaultManager] removeItemAtPath:markPath error:nil];
		[[NSFileManager defaultManager] removeItemAtPath:helperPath error:nil];

		[[NSFileManager defaultManager] moveItemAtPath:backupPath toPath:executablePath error:nil];

		BKSTerminateApplicationForReasonAndReportWithDescription(systemAppProxy.bundleIdentifier, 5, false, @"TrollStore - Reload persistence helper");
	}

	LSApplicationProxy* userAppProxy = findPersistenceHelperApp(PERSISTENCE_HELPER_TYPE_USER);
	if(userAppProxy)
	{
		unregisterUserPersistenceHelper();
	}
}

void registerUserPersistenceHelper(NSString* userAppId)
{
	if(findPersistenceHelperApp(PERSISTENCE_HELPER_TYPE_ALL)) return;

	LSApplicationProxy* appProxy = [LSApplicationProxy applicationProxyForIdentifier:userAppId];
	if(!appProxy || ![appProxy.bundleType isEqualToString:@"User"]) return;

	NSString* markPath = [appProxy.bundleURL.path stringByAppendingPathComponent:@".TrollStorePersistenceHelper"];
	[[NSFileManager defaultManager] createFileAtPath:markPath contents:[NSData data] attributes:nil];
}

// Apparently there is some odd behaviour where TrollStore installed apps sometimes get restricted
// This works around that issue at least and is triggered when rebuilding icon cache
void cleanRestrictions(void)
{
	NSString* clientTruthPath = @"/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist";
	NSURL* clientTruthURL = [NSURL fileURLWithPath:clientTruthPath];
	NSDictionary* clientTruthDictionary = [NSDictionary dictionaryWithContentsOfURL:clientTruthURL];

	if(!clientTruthDictionary) return;

	NSArray* valuesArr;

	NSDictionary* lsdAppRemoval = clientTruthDictionary[@"com.apple.lsd.appremoval"];
	if(lsdAppRemoval && [lsdAppRemoval isKindOfClass:NSDictionary.class])
	{
		NSDictionary* clientRestrictions = lsdAppRemoval[@"clientRestrictions"];
		if(clientRestrictions && [clientRestrictions isKindOfClass:NSDictionary.class])
		{
			NSDictionary* unionDict = clientRestrictions[@"union"];
			if(unionDict && [unionDict isKindOfClass:NSDictionary.class])
			{
				NSDictionary* removedSystemAppBundleIDs = unionDict[@"removedSystemAppBundleIDs"];
				if(removedSystemAppBundleIDs && [removedSystemAppBundleIDs isKindOfClass:NSDictionary.class])
				{
					valuesArr = removedSystemAppBundleIDs[@"values"];
				}
			}
		}
	}

	if(!valuesArr || !valuesArr.count) return;

	NSMutableArray* valuesArrM = valuesArr.mutableCopy;
	__block BOOL changed = NO;

	[valuesArrM enumerateObjectsWithOptions:NSEnumerationReverse usingBlock:^(NSString* value, NSUInteger idx, BOOL *stop)
	{
		if(!isRemovableSystemApp(value))
		{
			[valuesArrM removeObjectAtIndex:idx];
			changed = YES;
		}
	}];

	if(!changed) return;

	NSMutableDictionary* clientTruthDictionaryM = (__bridge_transfer NSMutableDictionary*)CFPropertyListCreateDeepCopy(kCFAllocatorDefault, (__bridge CFDictionaryRef)clientTruthDictionary, kCFPropertyListMutableContainersAndLeaves);
	
	clientTruthDictionaryM[@"com.apple.lsd.appremoval"][@"clientRestrictions"][@"union"][@"removedSystemAppBundleIDs"][@"values"] = valuesArrM;

	[clientTruthDictionaryM writeToURL:clientTruthURL error:nil];

	killall(@"profiled", NO); // profiled needs to restart for the changes to apply
}

int MAIN_NAME(int argc, char *argv[], char *envp[])
{
	@autoreleasepool {
		if(argc <= 1) return -1;

		if(getuid() != 0)
		{
			NSLog(@"ERROR: trollstorehelper has to be run as root.");
			return -1;
		}

		NSMutableArray* args = [NSMutableArray new];
		for (int i = 1; i < argc; i++)
		{
			[args addObject:[NSString stringWithUTF8String:argv[i]]];
		}

		NSLog(@"trollstorehelper invoked with arguments: %@", args);

		int ret = 0;
		NSString* cmd = args.firstObject;
		if([cmd isEqualToString:@"install"])
		{
			NSString *ipaPath = nil;
			if (args.count >= 2) {
				ipaPath = args.lastObject;
			} else {
				const char *envPath = getenv("IPA_PATH") ?: getenv("K90_IPA");
				if (envPath && envPath[0]) {
					ipaPath = [NSString stringWithUTF8String:envPath];
				}
			}
			if (!ipaPath.length) return -3;
			BOOL useInstalldMethod = [args containsObject:@"installd"];
			BOOL explicitMethod = [args containsObject:@"custom"] || [args containsObject:@"installd"];
			BOOL force = [args containsObject:@"force"] || !explicitMethod;
			BOOL skipUICache = [args containsObject:@"skip-uicache"];
			ret = installIpa(ipaPath, force, useInstalldMethod, skipUICache);
			if (!explicitMethod) {
				if (ret == 0 || ret == 182 || ret == 184) {
					printf("trollstorehelper: installed %s\n", ipaPath.UTF8String);
					ret = 0;
				} else {
					fprintf(stderr, "trollstorehelper: install %s failed (%d)\n", ipaPath.UTF8String, ret);
				}
			}
		}
		else if([cmd isEqualToString:@"uninstall"] || [cmd isEqualToString:@"remove"])
		{
			if(args.count < 2) return -3;
			BOOL useCustomMethod = [args containsObject:@"custom"] || [cmd isEqualToString:@"remove"] || args.count == 2;
			NSString* appId = args.lastObject;
			ret = uninstallAppById(appId, useCustomMethod);
		}
		else if([cmd isEqualToString:@"list"])
		{
			listInstalledApps();
		}
		else if([cmd isEqualToString:@"open"])
		{
			if(args.count < 2) return -3;
			NSString *bid = args.lastObject;
			BOOL ok = [[LSApplicationWorkspace defaultWorkspace] openApplicationWithBundleID:bid];
			printf("trollstorehelper: %s %s\n", bid.UTF8String, ok ? "opened" : "NOT OPENED");
			ret = ok ? 0 : 1;
		}
		else if([cmd isEqualToString:@"url"])
		{
			if(args.count < 2) return -3;
			NSString *urlStr = args.lastObject;
			NSURL *u = [NSURL URLWithString:urlStr];
			BOOL ok = u ? [[LSApplicationWorkspace defaultWorkspace] openURL:u] : NO;
			printf("trollstorehelper: url %s %s\n", urlStr.UTF8String, ok ? "opened" : "FAILED");
			ret = ok ? 0 : 1;
		}
		else if([cmd isEqualToString:@"register-system"] || [cmd isEqualToString:@"register"] || [cmd isEqualToString:@"ensure-trollstore"])
		{
			ret = ensureTrollStoreInstalled();
		}
		else if([cmd isEqualToString:@"watch"])
		{
			ensureTrollStoreInstalled();
			NSFileManager *fm = [NSFileManager defaultManager];
			NSString *watchDir = @"/private/var/tmp/ipa";
			[fm createDirectoryAtPath:watchDir withIntermediateDirectories:YES attributes:nil error:nil];
			chmod(watchDir.fileSystemRepresentation, 01777);
			for (;;) {
				@autoreleasepool {
					for (NSString *item in [fm contentsOfDirectoryAtPath:watchDir error:nil]) {
						if (![item.pathExtension.lowercaseString isEqualToString:@"ipa"]) continue;
						if ([item hasPrefix:@"."]) continue;
						NSString *path = [watchDir stringByAppendingPathComponent:item];
						int r = installIpa(path, YES, NO, NO);
						if (r == 0 || r == 182 || r == 184) {
							[fm removeItemAtPath:path error:nil];
						}
					}
				}
				sleep(2);
			}
		}
		else if([cmd isEqualToString:@"uninstall-path"])
		{
			if(args.count < 2) return -3;
			// use custom method when specified, otherwise use system method
			BOOL useCustomMethod = [args containsObject:@"custom"];
			NSString* appPath = args.lastObject;
			ret = uninstallAppByPath(appPath, useCustomMethod);
		}
		else if([cmd isEqualToString:@"refresh"])
		{
			refreshAppRegistrations(!shouldRegisterAsUserByDefault());
		}
		else if([cmd isEqualToString:@"refresh-all"])
		{
			cleanRestrictions();
			//refreshAppRegistrations(NO); // <- fixes app permissions resetting, causes apps to move around on home screen, so I had to disable it
			[[NSFileManager defaultManager] removeItemAtPath:@"/var/containers/Shared/SystemGroup/systemgroup.com.apple.lsd.iconscache/Library/Caches/com.apple.IconsCache" error:nil];
			[[LSApplicationWorkspace defaultWorkspace] _LSPrivateRebuildApplicationDatabasesForSystemApps:YES internal:YES user:YES];
			if (!shouldRegisterAsUserByDefault()) refreshAppRegistrations(YES);
			killall(@"backboardd", YES);
		}
		else if([cmd isEqualToString:@"url-scheme"])
		{
			if(args.count < 2) return -3;
			NSString* modifyArg = args.lastObject;
			BOOL newState = [modifyArg isEqualToString:@"enable"];
			if(newState == YES || [modifyArg isEqualToString:@"disable"])
			{
				setTSURLSchemeState(newState, nil);
			}
		}
		else if([cmd isEqualToString:@"reboot"])
		{
			[[FBSSystemService sharedService] reboot];
			// Give the system some time to reboot
			sleep(1);
		}
		else if([cmd isEqualToString:@"enable-jit"])
		{
			if(args.count < 2) return -3;
			NSString* userAppId = args.lastObject;
			ret = enableJIT(userAppId);
		}
		else if([cmd isEqualToString:@"modify-registration"])
		{
			if(args.count < 3) return -3;
			NSString* appPath = args[1];
			NSString* newRegistration = args[2];

			NSString* trollStoreMark = [[appPath stringByDeletingLastPathComponent] stringByAppendingPathComponent:TS_ACTIVE_MARKER];
			if([[NSFileManager defaultManager] fileExistsAtPath:trollStoreMark])
			{
				registerPath(appPath, NO, [newRegistration isEqualToString:@"System"]);
			}
		}
		else if ([cmd isEqualToString:@"transfer-apps"])
		{
			bool oneFailed = false;
			for (NSString *appBundlePath in trollStoreInactiveInstalledAppBundlePaths()) {
				NSLog(@"Transfering %@...", appBundlePath);

				// Ldid lacks the entitlement to sign in place
				// So copy to /tmp, resign, then replace >.<
				NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
				if (![[NSFileManager defaultManager] createDirectoryAtPath:tmpPath withIntermediateDirectories:YES attributes:nil error:nil]) return -3;

				NSString *tmpAppPath = [tmpPath stringByAppendingPathComponent:appBundlePath.lastPathComponent];
				if (![[NSFileManager defaultManager] copyItemAtPath:appBundlePath toPath:tmpAppPath error:nil]) {
					[[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
					oneFailed = true;
					continue;
				}

				NSLog(@"Copied %@ to %@", appBundlePath, tmpAppPath);

				int signRet = signApp(tmpAppPath);
				NSLog(@"Signing %@ returned %d", tmpAppPath, signRet);

				if (signRet == 0 || signRet == 182 || signRet == 184) { // Either 0 or non fatal error codes are fine
					[[NSFileManager defaultManager] removeItemAtPath:appBundlePath error:nil];
					[[NSFileManager defaultManager] moveItemAtPath:tmpAppPath toPath:appBundlePath error:nil];
					[[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
				}
				else {
					[[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
					oneFailed = true;
					continue;
				}

				fixPermissionsOfAppBundle(appBundlePath);

				NSString *containerPath = [appBundlePath stringByDeletingLastPathComponent];
				NSString *activeMarkerPath = [containerPath stringByAppendingPathComponent:TS_ACTIVE_MARKER];
				NSString *inactiveMarkerPath = [containerPath stringByAppendingPathComponent:TS_INACTIVE_MARKER];

				NSData* emptyData = [NSData data];
				[emptyData writeToFile:activeMarkerPath options:0 error:nil];

				[[NSFileManager defaultManager] removeItemAtPath:inactiveMarkerPath error:nil];

				registerPath(appBundlePath, 0, !shouldRegisterAsUserByDefault());

				NSLog(@"Transfered %@!", appBundlePath);
			}
			if (oneFailed) ret = -1;
		}
#ifndef TROLLSTORE_LITE
		else if([cmd isEqualToString:@"install-trollstore"])
		{
			if(args.count < 2) return -3;
			NSString* tsTar = args.lastObject;
			ret = installTrollStore(tsTar);
			NSLog(@"installed troll store? %d", ret==0);
		}
		else if([cmd isEqualToString:@"uninstall-trollstore"])
		{
			if(![args containsObject:@"preserve-apps"])
			{
				uninstallAllApps([args containsObject:@"custom"]);
			}
			uninstallTrollStore(YES);
		}
		else if([cmd isEqualToString:@"install-ldid"])
		{
			//if (@available(iOS 16, *)) {} else {
				if(args.count < 3) return -3;
				NSString* ldidPath = args[1];
				NSString* ldidVersion = args[2];
				installLdid(ldidPath, ldidVersion);
			//}
		}
		else if([cmd isEqualToString:@"install-persistence-helper"])
		{
			if(args.count < 2) return -3;
			NSString* systemAppId = args[1];
			NSString* persistenceHelperBinary;
			NSString* rootHelperBinary;
			if (args.count == 4) {
				persistenceHelperBinary = args[2];
				rootHelperBinary = args[3];
			}

			installPersistenceHelper(systemAppId, persistenceHelperBinary, rootHelperBinary);
		}
		else if([cmd isEqualToString:@"uninstall-persistence-helper"])
		{
			uninstallPersistenceHelper();
		}
		else if([cmd isEqualToString:@"register-user-persistence-helper"])
		{
			if(args.count < 2) return -3;
			NSString* userAppId = args.lastObject;
			registerUserPersistenceHelper(userAppId);
		}
		else if([cmd isEqualToString:@"check-dev-mode"])
		{
			// switch the result, so 0 is enabled, and 1 is disabled/error
			ret = !checkDeveloperMode();
		}
		else if([cmd isEqualToString:@"arm-dev-mode"])
		{
			// assumes that checkDeveloperMode() has already been called
			ret = !armDeveloperMode(NULL);
		}
#endif

		NSLog(@"trollstorehelper returning %d", ret);
		return ret;
	}
}
