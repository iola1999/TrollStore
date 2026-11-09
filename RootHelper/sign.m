#import "sign.h"
#import <TSUtil.h>
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <sys/stat.h>

NSDictionary *infoDictionaryForAppPath(NSString *appPath)
{
	if (!appPath) return nil;
	NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
	return [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
}

NSString *appIdForAppPath(NSString *appPath)
{
	if (!appPath) return nil;
	return infoDictionaryForAppPath(appPath)[@"CFBundleIdentifier"];
}

NSString *appMainExecutablePathForAppPath(NSString *appPath)
{
	if (!appPath) return nil;
	NSString *exec = infoDictionaryForAppPath(appPath)[@"CFBundleExecutable"];
	if (!exec) return nil;
	return [appPath stringByAppendingPathComponent:exec];
}

BOOL isMachoFile(NSString *filePath)
{
	FILE *file = fopen(filePath.fileSystemRepresentation, "r");
	if (!file) return NO;

	uint32_t magic = 0;
	size_t n = fread(&magic, sizeof(uint32_t), 1, file);
	fclose(file);
	if (n != 1) return NO;

	return magic == FAT_MAGIC || magic == FAT_CIGAM ||
	       magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64 ||
	       magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
	       magic == MH_MAGIC || magic == MH_CIGAM;
}

BOOL isSameFile(NSString *path1, NSString *path2)
{
	struct stat sb1;
	struct stat sb2;
	if (stat(path1.fileSystemRepresentation, &sb1) != 0) return NO;
	if (stat(path2.fileSystemRepresentation, &sb2) != 0) return NO;
	return sb1.st_dev == sb2.st_dev && sb1.st_ino == sb2.st_ino;
}

void installLdid(NSString *ldidToCopyPath, NSString *ldidVersion)
{
	if (![[NSFileManager defaultManager] fileExistsAtPath:ldidToCopyPath]) return;

	NSString *tsApp = trollStoreAppPath();
	if (!tsApp) return;
	NSString *ldidPath = [tsApp stringByAppendingPathComponent:@"ldid"];
	NSString *ldidVersionPath = [tsApp stringByAppendingPathComponent:@"ldid.version"];

	[[NSFileManager defaultManager] removeItemAtPath:ldidPath error:nil];
	[[NSFileManager defaultManager] copyItemAtPath:ldidToCopyPath toPath:ldidPath error:nil];

	NSData *ldidVersionData = [ldidVersion dataUsingEncoding:NSUTF8StringEncoding];
	[ldidVersionData writeToFile:ldidVersionPath atomically:YES];

	chmod(ldidPath.fileSystemRepresentation, 0755);
	chmod(ldidVersionPath.fileSystemRepresentation, 0644);
}

BOOL isLdidInstalled(void)
{
	return YES;
}

NSString *getLdidPath(void)
{
	return [trollStoreAppPath() stringByAppendingPathComponent:@"ldid"];
}

/* Extract the preferred ARM64 slice from a Fat Mach-O if needed. */
static NSMutableData *extractPreferredSliceData(NSData *rawData)
{
	if (!rawData || rawData.length < sizeof(uint32_t)) return nil;
	const uint8_t *bytes = (const uint8_t *)rawData.bytes;
	size_t length = rawData.length;
	uint32_t magic = *(const uint32_t *)bytes;

	if (magic == MH_MAGIC_64) {
		return [rawData mutableCopy];
	}
	if (magic == FAT_CIGAM && length >= sizeof(struct fat_header)) {
		uint32_t nfat = ntohl(((const struct fat_header *)bytes)->nfat_arch);
		if (sizeof(struct fat_header) + (size_t)nfat * sizeof(struct fat_arch) > length) {
			return nil;
		}
		const struct fat_arch *archs = (const struct fat_arch *)(bytes + sizeof(struct fat_header));
		uint32_t bestOffset = 0;
		uint32_t bestSize = 0;
		BOOL foundArm64e = NO;

		for (uint32_t i = 0; i < nfat; i++) {
			cpu_type_t cputype = (cpu_type_t)ntohl(archs[i].cputype);
			cpu_subtype_t cpusubtype = (cpu_subtype_t)ntohl(archs[i].cpusubtype);
			uint32_t offset = ntohl(archs[i].offset);
			uint32_t size = ntohl(archs[i].size);
			if (cputype != CPU_TYPE_ARM64 || (size_t)offset + size > length) {
				continue;
			}
			uint32_t sub = (uint32_t)cpusubtype & ~CPU_SUBTYPE_MASK;
			if (sub == CPU_SUBTYPE_ARM64E) {
				bestOffset = offset;
				bestSize = size;
				foundArm64e = YES;
				break;
			}
			if (!foundArm64e && bestSize == 0) {
				bestOffset = offset;
				bestSize = size;
			}
		}
		if (bestSize > 0) {
			return [[rawData subdataWithRange:NSMakeRange(bestOffset, bestSize)] mutableCopy];
		}
	}
	return nil;
}

static BOOL isSliceEncrypted(NSData *sliceData)
{
	if (!sliceData || sliceData.length < sizeof(struct mach_header_64)) return NO;
	const uint8_t *bytes = (const uint8_t *)sliceData.bytes;
	if (*(const uint32_t *)bytes != MH_MAGIC_64) return NO;

	const struct mach_header_64 *mh = (const struct mach_header_64 *)bytes;
	size_t at = sizeof(struct mach_header_64);
	for (uint32_t i = 0; i < mh->ncmds; i++) {
		if (at + sizeof(struct load_command) > sliceData.length) break;
		const struct load_command *lc = (const struct load_command *)(bytes + at);
		if (lc->cmdsize < sizeof(struct load_command) || at + lc->cmdsize > sliceData.length) break;
		if (lc->cmd == LC_ENCRYPTION_INFO_64 && lc->cmdsize >= sizeof(struct encryption_info_command_64)) {
			const struct encryption_info_command_64 *enc = (const struct encryption_info_command_64 *)lc;
			if (enc->cryptid != 0) return YES;
		}
		at += lc->cmdsize;
	}
	return NO;
}

/*
 * Sign a single 64-bit Mach-O binary in-place with an ad-hoc SHA-256 CodeDirectory (version 0x20100)
 * and XML entitlements blob (0xfade7171). Returns 0 on success, 180 if FairPlay-encrypted, 175 on error.
 */
static int signMachOFile(NSString *path, NSDictionary *entitlements)
{
	NSData *rawData = [NSData dataWithContentsOfFile:path];
	NSMutableData *data = extractPreferredSliceData(rawData);
	if (!data || data.length < sizeof(struct mach_header_64)) {
		return 175;
	}
	if (isSliceEncrypted(data)) {
		return 180;
	}

	struct mach_header_64 *mh = (struct mach_header_64 *)data.mutableBytes;
	uint32_t at = sizeof(struct mach_header_64);
	uint32_t cs_cmd_offset = 0;
	uint32_t linkedit_cmd_offset = 0;
	uint32_t first_fileoff = (uint32_t)data.length;
	uint32_t orig_dataoff = 0;
	uint32_t orig_datasize = 0;

	for (uint32_t i = 0; i < mh->ncmds; i++) {
		if (at + sizeof(struct load_command) > data.length) return 175;
		struct load_command *lc = (struct load_command *)((uint8_t *)data.mutableBytes + at);
		if (lc->cmdsize < sizeof(struct load_command) || at + lc->cmdsize > data.length) return 175;
		if (lc->cmd == LC_SEGMENT_64) {
			struct segment_command_64 *seg = (struct segment_command_64 *)lc;
			if (strcmp(seg->segname, "__LINKEDIT") == 0) {
				linkedit_cmd_offset = at;
			}
			if (seg->fileoff > 0 && seg->fileoff < first_fileoff) {
				first_fileoff = (uint32_t)seg->fileoff;
			}
		} else if (lc->cmd == LC_CODE_SIGNATURE) {
			cs_cmd_offset = at;
			struct linkedit_data_command *cs = (struct linkedit_data_command *)lc;
			orig_dataoff = cs->dataoff;
			orig_datasize = cs->datasize;
		}
		at += lc->cmdsize;
	}
	if (linkedit_cmd_offset == 0) {
		return 175;
	}

	NSMutableDictionary *ent = [NSMutableDictionary dictionary];
	if (cs_cmd_offset != 0 && (size_t)orig_dataoff + orig_datasize <= data.length && orig_datasize >= 12) {
		const uint8_t *sb_bytes = (const uint8_t *)data.bytes + orig_dataoff;
		uint32_t sb_magic = ntohl(*(const uint32_t *)sb_bytes);
		uint32_t sb_count = ntohl(*(const uint32_t *)(sb_bytes + 8));
		if (sb_magic == 0xfade0cc0 && 12 + (size_t)sb_count * 8 <= orig_datasize) {
			for (uint32_t i = 0; i < sb_count; i++) {
				uint32_t stype = ntohl(*(const uint32_t *)(sb_bytes + 12 + i * 8));
				uint32_t soff = ntohl(*(const uint32_t *)(sb_bytes + 16 + i * 8));
				if (stype == 5 && (size_t)soff + 8 <= orig_datasize) {
					uint32_t emagic = ntohl(*(const uint32_t *)(sb_bytes + soff));
					uint32_t elen = ntohl(*(const uint32_t *)(sb_bytes + soff + 4));
					if (emagic == 0xfade7171 && elen >= 8 && (size_t)soff + elen <= orig_datasize) {
						NSData *exData = [NSData dataWithBytes:sb_bytes + soff + 8 length:elen - 8];
						NSDictionary *existing = [NSPropertyListSerialization propertyListWithData:exData
						                                                                   options:0
						                                                                    format:NULL
						                                                                     error:nil];
						if ([existing isKindOfClass:[NSDictionary class]]) {
							[ent addEntriesFromDictionary:existing];
						}
					}
				}
			}
		}
	}

	if (entitlements) {
		[ent addEntriesFromDictionary:entitlements];
	}
	ent[@"get-task-allow"] = @YES;

	NSData *xml = [NSPropertyListSerialization dataWithPropertyList:ent
	                                                         format:NSPropertyListXMLFormat_v1_0
	                                                        options:0
	                                                          error:nil];
	if (!xml) return 175;

	uint32_t ent_blob_len = 8 + (uint32_t)xml.length;
	NSMutableData *ent_blob = [NSMutableData dataWithLength:ent_blob_len];
	uint32_t *eh = (uint32_t *)ent_blob.mutableBytes;
	eh[0] = htonl(0xfade7171);
	eh[1] = htonl(ent_blob_len);
	memcpy((uint8_t *)ent_blob.mutableBytes + 8, xml.bytes, xml.length);

	uint8_t ent_hash[32];
	CC_SHA256(ent_blob.bytes, (CC_LONG)ent_blob.length, ent_hash);

	uint32_t req_blob[3] = { htonl(0xfade0c01), htonl(12), 0 };
	uint8_t req_hash[32];
	CC_SHA256(req_blob, 12, req_hash);

	uint32_t sig_blob[2] = { htonl(0xfade0b01), htonl(8) };

	uint32_t codeLimit = (cs_cmd_offset != 0) ? orig_dataoff : (uint32_t)data.length;
	if (data.length > codeLimit) {
		[data setLength:codeLimit];
	}
	while (codeLimit % 16 != 0) {
		[data appendBytes:"\0" length:1];
		codeLimit++;
	}

	uint32_t nCodeSlots = (codeLimit + 4095) / 4096;
	uint32_t nSpecialSlots = 5;
	const char *ident = [path.lastPathComponent.stringByDeletingPathExtension UTF8String];
	if (!ident || strlen(ident) == 0) ident = "binary";

	/* Version 0x20100 places scatterOffset at byte 44 (0 = none) and identifier at byte 48. */
	uint32_t ident_offset = 48;
	uint32_t hash_offset = ident_offset + (uint32_t)strlen(ident) + 1;
	while (hash_offset % 4 != 0) hash_offset++;
	uint32_t actual_hash_offset = hash_offset + nSpecialSlots * 32;
	uint32_t cd_length = actual_hash_offset + nCodeSlots * 32;

	NSMutableData *cd_data = [NSMutableData dataWithLength:cd_length];
	uint32_t *cd_words = (uint32_t *)cd_data.mutableBytes;
	cd_words[0] = htonl(0xfade0c02);
	cd_words[1] = htonl(cd_length);
	cd_words[2] = htonl(0x20100);
	cd_words[3] = htonl(0x00000006);
	cd_words[4] = htonl(actual_hash_offset);
	cd_words[5] = htonl(ident_offset);
	cd_words[6] = htonl(nSpecialSlots);
	cd_words[7] = htonl(nCodeSlots);
	cd_words[8] = htonl(codeLimit);
	uint8_t *cd_bytes = (uint8_t *)cd_data.mutableBytes;
	cd_bytes[36] = 32;
	cd_bytes[37] = 2;
	cd_bytes[38] = 0;
	cd_bytes[39] = 12;
	memcpy(cd_bytes + ident_offset, ident, strlen(ident) + 1);

	memcpy(cd_bytes + actual_hash_offset - 2 * 32, req_hash, 32);
	memcpy(cd_bytes + actual_hash_offset - 5 * 32, ent_hash, 32);

	uint32_t sb_index_size = 12 + 4 * 8;
	uint32_t cd_offset = (sb_index_size + 15) & ~15;
	uint32_t req_offset = (cd_offset + (uint32_t)cd_data.length + 15) & ~15;
	uint32_t ent_offset_val = (req_offset + 12 + 15) & ~15;
	uint32_t sig_offset = (ent_offset_val + (uint32_t)ent_blob.length + 15) & ~15;
	uint32_t sb_total_size = (sig_offset + 8 + 15) & ~15;

	/* Update load commands before computing page hashes so page 0/1 hashes match the updated header. */
	mh = (struct mach_header_64 *)data.mutableBytes;
	struct segment_command_64 *linkedit_cmd = (struct segment_command_64 *)((uint8_t *)data.mutableBytes + linkedit_cmd_offset);

	if (cs_cmd_offset != 0) {
		struct linkedit_data_command *cs_cmd = (struct linkedit_data_command *)((uint8_t *)data.mutableBytes + cs_cmd_offset);
		cs_cmd->dataoff = codeLimit;
		cs_cmd->datasize = sb_total_size;
	} else {
		if (first_fileoff < sizeof(struct mach_header_64) + mh->sizeofcmds + sizeof(struct linkedit_data_command)) {
			return 175;
		}
		struct linkedit_data_command *new_cs = (struct linkedit_data_command *)((uint8_t *)data.mutableBytes + sizeof(struct mach_header_64) + mh->sizeofcmds);
		memset(new_cs, 0, sizeof(*new_cs));
		new_cs->cmd = LC_CODE_SIGNATURE;
		new_cs->cmdsize = sizeof(*new_cs);
		new_cs->dataoff = codeLimit;
		new_cs->datasize = sb_total_size;

		mh->ncmds += 1;
		mh->sizeofcmds += sizeof(*new_cs);
	}

	linkedit_cmd->filesize = (codeLimit + sb_total_size) - linkedit_cmd->fileoff;
	linkedit_cmd->vmsize = (linkedit_cmd->filesize + 0x3fff) & ~0x3fff;

	for (uint32_t p = 0; p < nCodeSlots; p++) {
		uint32_t pstart = p * 4096;
		uint32_t plen = (pstart + 4096 <= codeLimit) ? 4096 : (codeLimit - pstart);
		CC_SHA256((const uint8_t *)data.bytes + pstart, plen, cd_bytes + actual_hash_offset + p * 32);
	}

	NSMutableData *sb = [NSMutableData dataWithLength:sb_total_size];
	uint32_t *sb_words = (uint32_t *)sb.mutableBytes;
	sb_words[0] = htonl(0xfade0cc0);
	sb_words[1] = htonl(sb_total_size);
	sb_words[2] = htonl(4);
	sb_words[3] = htonl(0);
	sb_words[4] = htonl(cd_offset);
	sb_words[5] = htonl(2);
	sb_words[6] = htonl(req_offset);
	sb_words[7] = htonl(5);
	sb_words[8] = htonl(ent_offset_val);
	sb_words[9] = htonl(0x10000);
	sb_words[10] = htonl(sig_offset);

	memcpy((uint8_t *)sb.mutableBytes + cd_offset, cd_data.bytes, cd_data.length);
	memcpy((uint8_t *)sb.mutableBytes + req_offset, req_blob, 12);
	memcpy((uint8_t *)sb.mutableBytes + ent_offset_val, ent_blob.bytes, ent_blob.length);
	memcpy((uint8_t *)sb.mutableBytes + sig_offset, sig_blob, 8);

	[data appendData:sb];

	if (![data writeToFile:path atomically:YES]) {
		return 175;
	}
	chmod(path.fileSystemRepresentation, 0755);
	return 0;
}

int signAdhoc(NSString *filePath, NSDictionary *entitlements)
{
	BOOL isDir = NO;
	if (![[NSFileManager defaultManager] fileExistsAtPath:filePath isDirectory:&isDir]) {
		return 174;
	}
	if (!isDir) {
		return signMachOFile(filePath, entitlements);
	}

	NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:filePath]
	                                                         includingPropertiesForKeys:nil
	                                                                            options:0
	                                                                       errorHandler:nil];
	for (NSURL *fileURL in enumerator) {
		NSString *subPath = fileURL.path;
		BOOL subDir = NO;
		if ([[NSFileManager defaultManager] fileExistsAtPath:subPath isDirectory:&subDir] && !subDir && isMachoFile(subPath)) {
			int r = signMachOFile(subPath, nil);
			if (r != 0 && r != 180) {
				return r;
			}
		}
	}
	return 0;
}

int signApp(NSString *appPath)
{
	NSDictionary *appInfoDict = infoDictionaryForAppPath(appPath);
	if (!appInfoDict) return 172;

	NSString *mainExecutablePath = appMainExecutablePathForAppPath(appPath);
	if (!mainExecutablePath) return 176;

	if (![[NSFileManager defaultManager] fileExistsAtPath:mainExecutablePath]) return 174;

	BOOL hasAdditionalEncryptedBinaries = NO;
	NSMutableSet<NSString *> *signedBundleExecutables = [NSMutableSet set];

	NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:appPath]
	                                                         includingPropertiesForKeys:nil
	                                                                            options:0
	                                                                       errorHandler:nil];
	for (NSURL *fileURL in enumerator) {
		NSString *filePath = fileURL.path;
		if (![filePath.lastPathComponent isEqualToString:@"Info.plist"]) continue;

		NSDictionary *infoDict = [NSDictionary dictionaryWithContentsOfFile:filePath];
		if (!infoDict) continue;
		NSString *bundleId = infoDict[@"CFBundleIdentifier"];
		NSString *bundleExecutable = infoDict[@"CFBundleExecutable"];
		if (!bundleId || !bundleExecutable || bundleId.length == 0 || bundleExecutable.length == 0) continue;

		NSString *bundleMainExecutablePath = [[filePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:bundleExecutable];
		if (![[NSFileManager defaultManager] fileExistsAtPath:bundleMainExecutablePath]) continue;

		NSString *packageType = infoDict[@"CFBundlePackageType"];
		if ([packageType isEqualToString:@"FMWK"]) continue;

		NSMutableDictionary *entitlementsToUse = dumpEntitlementsFromBinaryAtPath(bundleMainExecutablePath).mutableCopy;
		if (isSameFile(bundleMainExecutablePath, mainExecutablePath) && !entitlementsToUse) {
			entitlementsToUse = @{
				@"application-identifier": @"TROLLTROLL.*",
				@"com.apple.developer.team-identifier": @"TROLLTROLL",
				@"get-task-allow": @YES,
				@"keychain-access-groups": @[
					@"TROLLTROLL.*",
					@"com.apple.token"
				],
			}.mutableCopy;
		}
		if (!entitlementsToUse) {
			entitlementsToUse = [NSMutableDictionary new];
		}

		NSObject *containerRequiredO = entitlementsToUse[@"com.apple.private.security.container-required"];
		BOOL containerRequired = YES;
		if ([containerRequiredO isKindOfClass:[NSNumber class]]) {
			containerRequired = [(NSNumber *)containerRequiredO boolValue];
		} else if ([containerRequiredO isKindOfClass:[NSString class]]) {
			containerRequired = NO;
		}
		if (containerRequired) {
			BOOL noContainer = [entitlementsToUse[@"com.apple.private.security.no-container"] respondsToSelector:@selector(boolValue)] &&
			                   [entitlementsToUse[@"com.apple.private.security.no-container"] boolValue];
			BOOL noSandbox = [entitlementsToUse[@"com.apple.private.security.no-sandbox"] respondsToSelector:@selector(boolValue)] &&
			                 [entitlementsToUse[@"com.apple.private.security.no-sandbox"] boolValue];
			if (!noContainer && !noSandbox) {
				entitlementsToUse[@"com.apple.private.security.container-required"] = bundleId;
			}
		}

		int r = signMachOFile(bundleMainExecutablePath, entitlementsToUse);
		if (r == 180) {
			if (isSameFile(bundleMainExecutablePath, mainExecutablePath)) {
				return 180;
			}
			hasAdditionalEncryptedBinaries = YES;
		} else if (r != 0) {
			return r;
		}
		[signedBundleExecutables addObject:bundleMainExecutablePath.stringByStandardizingPath];
	}

	enumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:appPath]
	                                  includingPropertiesForKeys:nil
	                                                     options:0
	                                                errorHandler:nil];
	for (NSURL *fileURL in enumerator) {
		NSString *filePath = fileURL.path.stringByStandardizingPath;
		if ([signedBundleExecutables containsObject:filePath]) continue;

		BOOL isDir = NO;
		if (![[NSFileManager defaultManager] fileExistsAtPath:filePath isDirectory:&isDir] || isDir) continue;
		if (!isMachoFile(filePath)) continue;

		int r = signMachOFile(filePath, nil);
		if (r == 180) {
			if (isSameFile(filePath, mainExecutablePath)) {
				return 180;
			}
			hasAdditionalEncryptedBinaries = YES;
		} else if (r != 0) {
			return r;
		}
	}

	if (hasAdditionalEncryptedBinaries) {
		return 184;
	}
	return 0;
}
