#import <Foundation/Foundation.h>
#import <CoreServices/CoreServices.h>
#import "CoreServices.h"
#import <objc/runtime.h>
#import "dlfcn.h"
#import <TSUtil.h>
#import <version.h>
#import "sign.h"
#include <CommonCrypto/CommonDigest.h>
#include <notify.h>
#include <sys/stat.h>
#include <unistd.h>

// uicache on steroids

extern NSSet<NSString*>* immutableAppBundleIdentifiers(void);
extern NSDictionary* dumpEntitlementsFromBinaryAtPath(NSString* binaryPath);

NSDictionary *constructGroupsContainersForEntitlements(NSDictionary *entitlements, BOOL systemGroups) {
	if (!entitlements) return nil;

	NSString *entitlementForGroups;
	Class mcmClass;
	if (systemGroups) {
		entitlementForGroups = @"com.apple.security.system-groups";
		mcmClass = [MCMSystemDataContainer class];
	}
	else {
		entitlementForGroups = @"com.apple.security.application-groups";
		mcmClass = [MCMSharedDataContainer class];
	}

	NSArray *groupIDs = entitlements[entitlementForGroups];
	if (groupIDs && [groupIDs isKindOfClass:[NSArray class]]) {
		NSMutableDictionary *groupContainers = [NSMutableDictionary new];

		for (NSString *groupID in groupIDs) {
			MCMContainer *container = [mcmClass containerWithIdentifier:groupID createIfNecessary:YES existed:nil error:nil];
			if (container.url) {
				groupContainers[groupID] = container.url.path;
			}
		}

		return groupContainers.copy;
	}

	return nil;
}

BOOL constructContainerizationForEntitlements(NSDictionary *entitlements, NSString **customContainerOut) {
	NSNumber *noContainer = entitlements[@"com.apple.private.security.no-container"];
	if (noContainer && [noContainer isKindOfClass:[NSNumber class]]) {
		if (noContainer.boolValue) {
			return NO;
		}
	}

	NSObject *containerRequired = entitlements[@"com.apple.private.security.container-required"];
	if (containerRequired && [containerRequired isKindOfClass:[NSNumber class]]) {
		if (!((NSNumber *)containerRequired).boolValue) {
			return NO;
		}
	}
	else if (containerRequired && [containerRequired isKindOfClass:[NSString class]]) {
		*customContainerOut = (NSString *)containerRequired;
	}

	return YES;
}

NSString *constructTeamIdentifierForEntitlements(NSDictionary *entitlements) {
	NSString *teamIdentifier = entitlements[@"com.apple.developer.team-identifier"];
	if (teamIdentifier && [teamIdentifier isKindOfClass:[NSString class]]) {
		return teamIdentifier;
	}
	return nil;
}

NSDictionary *constructEnvironmentVariablesForContainerPath(NSString *containerPath, BOOL isContainerized) {
	NSString *homeDir = isContainerized ? containerPath : @"/var/mobile";
	NSString *tmpDir = isContainerized ? [containerPath stringByAppendingPathComponent:@"tmp"] : @"/var/tmp";
	return @{
		@"CFFIXED_USER_HOME" : homeDir,
		@"HOME" : homeDir,
		@"TMPDIR" : tmpDir
	};
}

bool registerPath(NSString *path, BOOL unregister, BOOL forceSystem) {
	if (!path) return false;

	LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];
	if (unregister && ![[NSFileManager defaultManager] fileExistsAtPath:path]) {
		LSApplicationProxy *app = [LSApplicationProxy applicationProxyForIdentifier:path];
		if (app.bundleURL) {
			path = [app bundleURL].path;
		}
	}

	path = path.stringByResolvingSymlinksInPath.stringByStandardizingPath;

	NSDictionary *appInfoPlist = [NSDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"Info.plist"]];
	NSString *appBundleID = [appInfoPlist objectForKey:@"CFBundleIdentifier"];

	if([immutableAppBundleIdentifiers() containsObject:appBundleID.lowercaseString]) return false;

	if (appBundleID && !unregister) {
		NSString *appExecutablePath = [path stringByAppendingPathComponent:appInfoPlist[@"CFBundleExecutable"]];
		NSDictionary *entitlements = dumpEntitlementsFromBinaryAtPath(appExecutablePath);

		NSString *appDataContainerID = appBundleID;
		BOOL appContainerized = constructContainerizationForEntitlements(entitlements, &appDataContainerID);

		MCMContainer *appDataContainer = [NSClassFromString(@"MCMAppDataContainer") containerWithIdentifier:appDataContainerID createIfNecessary:YES existed:nil error:nil];
		NSString *containerPath = [appDataContainer url].path;

		BOOL isRemovableSystemApp = [[NSFileManager defaultManager] fileExistsAtPath:[@"/System/Library/AppSignatures" stringByAppendingPathComponent:appBundleID]];
		BOOL registerAsUser = [path hasPrefix:@"/var/containers"] && !isRemovableSystemApp && !forceSystem;

		NSMutableDictionary *dictToRegister = [NSMutableDictionary dictionary];

		// Add entitlements

		if (entitlements) {
			dictToRegister[@"Entitlements"] = entitlements;
		}

		// Misc
	
		dictToRegister[@"ApplicationType"] = registerAsUser ? @"User" : @"System";
		dictToRegister[@"CFBundleIdentifier"] = appBundleID;
		dictToRegister[@"CodeInfoIdentifier"] = appBundleID;
		dictToRegister[@"CompatibilityState"] = @0;
		dictToRegister[@"IsContainerized"] = @(appContainerized);
		if (containerPath) {
			dictToRegister[@"Container"] = containerPath;
			dictToRegister[@"EnvironmentVariables"] = constructEnvironmentVariablesForContainerPath(containerPath, appContainerized);
		}
		dictToRegister[@"IsDeletable"] = @(![appBundleID isEqualToString:APP_ID] && kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_15_0);
		dictToRegister[@"Path"] = path;
		for (NSString *key in @[@"CFBundleName", @"CFBundleDisplayName", @"CFBundlePackageType",
		                        @"CFBundleShortVersionString", @"CFBundleVersion",
		                        @"CFBundleIcons", @"CFBundleIcons~ipad", @"CFBundleIconFiles", @"CFBundleIconFile"]) {
			if (appInfoPlist[key]) {
				dictToRegister[key] = appInfoPlist[key];
			}
		}
		
		dictToRegister[@"SignerOrganization"] = @"Apple Inc.";
		dictToRegister[@"SignatureVersion"] = @132352;
		dictToRegister[@"SignerIdentity"] = @"Apple iPhone OS Application Signing";
		dictToRegister[@"IsAdHocSigned"] = @YES;
		dictToRegister[@"LSInstallType"] = @1;
		dictToRegister[@"HasMIDBasedSINF"] = @0;
		dictToRegister[@"MissingSINF"] = @0;
		dictToRegister[@"FamilyID"] = @0;
		dictToRegister[@"IsOnDemandInstallCapable"] = @0;

		NSString *teamIdentifier = constructTeamIdentifierForEntitlements(entitlements);
		if (teamIdentifier) dictToRegister[@"TeamIdentifier"] = teamIdentifier;

		// Add group containers

		NSDictionary *appGroupContainers = constructGroupsContainersForEntitlements(entitlements, NO);
		NSDictionary *systemGroupContainers = constructGroupsContainersForEntitlements(entitlements, YES);
		NSMutableDictionary *groupContainers = [NSMutableDictionary new];
		[groupContainers addEntriesFromDictionary:appGroupContainers];
		[groupContainers addEntriesFromDictionary:systemGroupContainers];
		if (groupContainers.count) {
			if (appGroupContainers.count) {
				dictToRegister[@"HasAppGroupContainers"] = @YES;
			}
			if (systemGroupContainers.count) {
				dictToRegister[@"HasSystemGroupContainers"] = @YES;
			}
			dictToRegister[@"GroupContainers"] = groupContainers.copy;
		}

		// Add plugins

		NSString *pluginsPath = [path stringByAppendingPathComponent:@"PlugIns"];
		NSArray *plugins = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:pluginsPath error:nil];

		NSMutableDictionary *bundlePlugins = [NSMutableDictionary dictionary];
		for (NSString *pluginName in plugins) {
			NSString *pluginPath = [pluginsPath stringByAppendingPathComponent:pluginName];

			NSDictionary *pluginInfoPlist = [NSDictionary dictionaryWithContentsOfFile:[pluginPath stringByAppendingPathComponent:@"Info.plist"]];
			NSString *pluginBundleID = [pluginInfoPlist objectForKey:@"CFBundleIdentifier"];

			if (!pluginBundleID) continue;
			NSString *pluginExecutablePath = [pluginPath stringByAppendingPathComponent:pluginInfoPlist[@"CFBundleExecutable"]];
			NSDictionary *pluginEntitlements = dumpEntitlementsFromBinaryAtPath(pluginExecutablePath);
			NSString *pluginDataContainerID = pluginBundleID;
			BOOL pluginContainerized = constructContainerizationForEntitlements(pluginEntitlements, &pluginDataContainerID);

			MCMContainer *pluginContainer = [NSClassFromString(@"MCMPluginKitPluginDataContainer") containerWithIdentifier:pluginDataContainerID createIfNecessary:YES existed:nil error:nil];
			NSString *pluginContainerPath = [pluginContainer url].path;

			NSMutableDictionary *pluginDict = [NSMutableDictionary dictionary];

			// Add entitlements
			if (pluginEntitlements) {
				pluginDict[@"Entitlements"] = pluginEntitlements;
			}

			// Misc

			pluginDict[@"ApplicationType"] = @"PluginKitPlugin";
			pluginDict[@"CFBundleIdentifier"] = pluginBundleID;
			pluginDict[@"CodeInfoIdentifier"] = pluginBundleID;
			pluginDict[@"CompatibilityState"] = @0;
			
			pluginDict[@"IsContainerized"] = @(pluginContainerized);
			if (pluginContainerPath) {
				pluginDict[@"Container"] = pluginContainerPath;
				pluginDict[@"EnvironmentVariables"] = constructEnvironmentVariablesForContainerPath(pluginContainerPath, pluginContainerized);
			}
			pluginDict[@"Path"] = pluginPath;
			pluginDict[@"PluginOwnerBundleID"] = appBundleID;
			pluginDict[@"SignerOrganization"] = @"Apple Inc.";
			pluginDict[@"SignatureVersion"] = @132352;
			pluginDict[@"SignerIdentity"] = @"Apple iPhone OS Application Signing";

			NSString *pluginTeamIdentifier = constructTeamIdentifierForEntitlements(pluginEntitlements);
			if (pluginTeamIdentifier) pluginDict[@"TeamIdentifier"] = pluginTeamIdentifier;

			// Add plugin group containers

			NSDictionary *pluginAppGroupContainers = constructGroupsContainersForEntitlements(pluginEntitlements, NO);
			NSDictionary *pluginSystemGroupContainers = constructGroupsContainersForEntitlements(pluginEntitlements, YES);
			NSMutableDictionary *pluginGroupContainers = [NSMutableDictionary new];
			[pluginGroupContainers addEntriesFromDictionary:pluginAppGroupContainers];
			[pluginGroupContainers addEntriesFromDictionary:pluginSystemGroupContainers];
			if (pluginGroupContainers.count) {
				if (pluginAppGroupContainers.count) {
					pluginDict[@"HasAppGroupContainers"] = @YES;
				}
				if (pluginSystemGroupContainers.count) {
					pluginDict[@"HasSystemGroupContainers"] = @YES;
				}
				pluginDict[@"GroupContainers"] = pluginGroupContainers.copy;
			}

			[bundlePlugins setObject:pluginDict forKey:pluginBundleID];
		}
		[dictToRegister setObject:bundlePlugins forKey:@"_LSBundlePlugins"];

		if (![workspace registerApplicationDictionary:dictToRegister]) {
			NSLog(@"Error: Unable to register %@", path);
			NSLog(@"Used dictionary: {");
			[dictToRegister enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSObject *obj, BOOL *stop) {
				NSLog(@"%@ = %@", key, obj);
			}];
			NSLog(@"}");
			return false;
		}
	} else {
		NSURL *url = [NSURL fileURLWithPath:path];
		if (![workspace unregisterApplication:url]) {
			NSLog(@"Error: Unable to register %@", path);
			return false;
		}
	}
	notify_post("com.apple.LaunchServices.ApplicationsChanged");
	notify_post("com.apple.LaunchServices.applicationRegistered");
	notify_post("com.annibale.var_save");
	sync();
	return true;
}

void fixPermissionsOfAppBundle(NSString *appBundlePath)
{
	NSURL *fileURL;
	NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:appBundlePath] includingPropertiesForKeys:nil options:0 errorHandler:nil];
	while ((fileURL = [enumerator nextObject])) {
		NSString *filePath = fileURL.path;
		chown(filePath.fileSystemRepresentation, 33, 33);
		chmod(filePath.fileSystemRepresentation, 0644);
	}

	enumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:appBundlePath] includingPropertiesForKeys:nil options:0 errorHandler:nil];
	while ((fileURL = [enumerator nextObject])) {
		NSString *filePath = fileURL.path;
		BOOL isDir = NO;
		[[NSFileManager defaultManager] fileExistsAtPath:filePath isDirectory:&isDir];
		if (isDir || isMachoFile(filePath)) {
			chmod(filePath.fileSystemRepresentation, 0755);
		}
	}

	NSString *helperPath = [appBundlePath stringByAppendingPathComponent:@"trollstorehelper"];
	if ([[NSFileManager defaultManager] fileExistsAtPath:helperPath]) {
		chown(helperPath.fileSystemRepresentation, 0, 0);
		chmod(helperPath.fileSystemRepresentation, 0755);
	}
}

static NSString *sha256HexOfFiles(NSArray<NSString *> *paths)
{
	CC_SHA256_CTX ctx;
	CC_SHA256_Init(&ctx);
	for (NSString *path in paths) {
		NSData *data = [NSData dataWithContentsOfFile:path];
		if (data.length > 0) {
			CC_SHA256_Update(&ctx, data.bytes, (CC_LONG)data.length);
		}
	}
	uint8_t digest[CC_SHA256_DIGEST_LENGTH];
	CC_SHA256_Final(digest, &ctx);
	NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
	for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
		[hex appendFormat:@"%02x", digest[i]];
	}
	return hex;
}

/*
 * Ensure /annibale/Applications/TrollStore.app is installed into its MCMAppContainer
 * and registered with LaunchServices, and mark any existing user app containers so
 * TrollStore recognizes them.
 */
int ensureTrollStoreInstalled(void)
{
	NSFileManager *fm = [NSFileManager defaultManager];
	for (int i = 0; i < 30; i++) {
		if ([LSApplicationWorkspace defaultWorkspace]) break;
		usleep(200000);
	}

	/* Mark any existing third-party app container in /private/var/containers/Bundle/Application with _TrollStore. */
	NSString *bundleRoot = @"/private/var/containers/Bundle/Application";
	for (NSString *uuid in [fm contentsOfDirectoryAtPath:bundleRoot error:nil]) {
		NSString *containerDir = [bundleRoot stringByAppendingPathComponent:uuid];
		for (NSString *item in [fm contentsOfDirectoryAtPath:containerDir error:nil]) {
			if (![item.pathExtension isEqualToString:@"app"]) continue;
			if ([item isEqualToString:@"TrollStore.app"]) continue;
			NSString *marker = [containerDir stringByAppendingPathComponent:TS_ACTIVE_MARKER];
			if (![fm fileExistsAtPath:marker]) {
				[[NSData data] writeToFile:marker atomically:YES];
			}
		}
	}

	NSString *srcApp = @"/annibale/Applications/TrollStore.app";
	if (![fm fileExistsAtPath:srcApp]) {
		return 0;
	}

	NSString *srcBin = [srcApp stringByAppendingPathComponent:@"TrollStore"];
	NSString *srcHelper = [srcApp stringByAppendingPathComponent:@"trollstorehelper"];
	if (![fm fileExistsAtPath:srcHelper]) {
		srcHelper = @"/annibale/bin/trollstorehelper";
	}
	NSString *wantDigest = sha256HexOfFiles(@[srcBin, srcHelper]);

	MCMAppContainer *container = [MCMAppContainer containerWithIdentifier:APP_ID createIfNecessary:NO existed:nil error:nil];
	if (container.url.path.length > 0) {
		NSString *dstApp = [container.url.path stringByAppendingPathComponent:@"TrollStore.app"];
		NSString *stampPath = [container.url.path stringByAppendingPathComponent:@".annibale-source-sha256"];
		NSString *haveDigest = [NSString stringWithContentsOfFile:stampPath encoding:NSUTF8StringEncoding error:nil];
		haveDigest = [haveDigest stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
		if ([fm fileExistsAtPath:dstApp] && [haveDigest isEqualToString:wantDigest]) {
			LSApplicationProxy *proxy = [LSApplicationProxy applicationProxyForIdentifier:APP_ID];
			if (!proxy.bundleURL) {
				registerPath(dstApp, NO, YES);
			}
			return 0;
		}
	}

	NSError *mcmErr = nil;
	container = [MCMAppContainer containerWithIdentifier:APP_ID createIfNecessary:YES existed:nil error:&mcmErr];
	if (!container.url.path.length) {
		NSLog(@"[ensureTrollStoreInstalled] failed to create MCMAppContainer: %@", mcmErr);
		return 170;
	}

	NSString *dstApp = [container.url.path stringByAppendingPathComponent:@"TrollStore.app"];
	[fm removeItemAtPath:dstApp error:nil];
	NSError *copyErr = nil;
	if (![fm copyItemAtPath:srcApp toPath:dstApp error:&copyErr]) {
		NSLog(@"[ensureTrollStoreInstalled] failed to copy %@ -> %@: %@", srcApp, dstApp, copyErr);
		return 178;
	}

	NSString *dstHelper = [dstApp stringByAppendingPathComponent:@"trollstorehelper"];
	if (![fm fileExistsAtPath:dstHelper] && [fm fileExistsAtPath:@"/annibale/bin/trollstorehelper"]) {
		[fm copyItemAtPath:@"/annibale/bin/trollstorehelper" toPath:dstHelper error:nil];
	}

	fixPermissionsOfAppBundle(dstApp);
	[[NSData data] writeToFile:[container.url.path stringByAppendingPathComponent:TS_ACTIVE_MARKER] atomically:YES];
	[wantDigest writeToFile:[container.url.path stringByAppendingPathComponent:@".annibale-source-sha256"]
	             atomically:YES
	               encoding:NSUTF8StringEncoding
	                  error:nil];

	if (!registerPath(dstApp, NO, YES)) {
		return 181;
	}
	return 0;
}

void listInstalledApps(void)
{
	NSFileManager *fm = [NSFileManager defaultManager];
	NSString *root = @"/private/var/containers/Bundle/Application";
	for (NSString *uuid in [fm contentsOfDirectoryAtPath:root error:nil]) {
		NSString *dir = [root stringByAppendingPathComponent:uuid];
		for (NSString *item in [fm contentsOfDirectoryAtPath:dir error:nil]) {
			if (![item.pathExtension.lowercaseString isEqualToString:@"app"]) continue;
			NSString *appPath = [dir stringByAppendingPathComponent:item];
			NSString *bid = appIdForAppPath(appPath);
			if (bid.length > 0) {
				printf("%s\t%s\n", bid.UTF8String, appPath.UTF8String);
			}
		}
	}
}
