//
//  EnvironmentManager.m
//  Dopamine
//
//  Created by Lars Fröder on 10.01.24.
//

#import "DOEnvironmentManager.h"
#import "UIImage+JPEG2000.h"

#import <sys/sysctl.h>
#import <sys/mount.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <unistd.h>
#import <mach-o/dyld.h>
#import <libgrabkernel2/libgrabkernel2.h>
#import <libjailbreak/info.h>
#import <libjailbreak/codesign.h>
#import <libjailbreak/util.h>
#import <libjailbreak/display.h>
#import <libjailbreak/machine_info.h>
#import <libjailbreak/carboncopy.h>

#import <IOKit/IOKitLib.h>
#import "DOUIManager.h"
#import "DOExploitManager.h"
#import "DOPreferenceManager.h"
#import "NSData+Hex.h"
#import <LocalAuthentication/LocalAuthentication.h>

int reboot3(uint64_t flags, ...);
CFPropertyListRef MGCopyAnswer(CFStringRef);
extern char **environ;

// iOS 27 Beta Support - Extended version checking
#define iOS_27_BETA_1 2701
#define iOS_27_BETA_2 2702
#define iOS_27_BETA_3 2703
#define iOS_27_BETA_4 2704

@implementation DOEnvironmentManager

+ (instancetype)sharedManager
{
    static DOEnvironmentManager *shared;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[DOEnvironmentManager alloc] init];
    });
    return shared;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _bootstrapNeedsMigration = NO;
        _bootstrapper = [[DOBootstrapper alloc] init];
        if ([self isJailbroken]) {
            gSystemInfo.jailbreakInfo.rootPath = strdup(jbclient_get_jbroot() ?: "");
        }
        else if ([self isInstalledThroughTrollStore]) {
            [self locateJailbreakRoot];
        }
    }
    return self;
}

- (NSString *)nightlyHash
{
#ifdef NIGHTLY
    return [NSString stringWithUTF8String:COMMIT_HASH];
#else
    return nil;
#endif
}

- (NSString *)appVersion
{
    return [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
}

- (NSString *)appVersionDisplayString
{
    NSString *nightlyHash = [self nightlyHash];
    if (nightlyHash) {
        return [NSString stringWithFormat:@"%@~%@", self.appVersion, [nightlyHash substringToIndex:6]];
    }
    else {
        return [self appVersion];
    }
}

- (NSString *)privatePrebootPath
{
    return @"/private/preboot";
}

- (NSString *)activePrebootPath
{
    NSString *bootManifestString = [NSString stringWithUTF8String:boot_manifest_hash()];
    return [[self privatePrebootPath] stringByAppendingPathComponent:bootManifestString];
}

// iOS 27 compatibility check
- (BOOL)isIOS27Beta
{
    return ([self getiOSMajorVersion] == 27);
}

- (int)getiOSMajorVersion
{
    NSDictionary *systemVersionDictionary = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    NSString *systemVersion = [systemVersionDictionary objectForKey:@"ProductVersion"];
    int majorVersion = [systemVersion intValue];
    return majorVersion;
}

- (void)locateJailbreakRoot
{
    if (!gSystemInfo.jailbreakInfo.rootPath) {
        NSString *activePrebootPath = [self activePrebootPath];
        
        NSString *randomizedJailbreakPath;
        
        // First attempt at finding jailbreak root, look for Dopamine 2.x path
        for (NSString *subItem in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:activePrebootPath error:nil]) {
            if (subItem.length == 15 && [subItem hasPrefix:@"dopamine-"]) {
                randomizedJailbreakPath = [activePrebootPath stringByAppendingPathComponent:subItem];
                break;
            }
        }
        
        if (!randomizedJailbreakPath) {
            // Second attempt at finding jailbreak root, look for Dopamine 1.x path, but as other jailbreaks use it too, make sure it is Dopamine
            // Some other jailbreaks also commit the sin of creating .installed_dopamine, for these we try to filter them out by checking for their installed_ file
            // If we find this and are sure it's from Dopamine 1.x, rename it so all Dopamine 2.x users will have the same path
            for (NSString *subItem in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:activePrebootPath error:nil]) {
                if (subItem.length == 9 && [subItem hasPrefix:@"jb-"]) {
                    NSString *candidateLegacyPath = [activePrebootPath stringByAppendingPathComponent:subItem];
                    
                    BOOL installedDopamine = [[NSFileManager defaultManager] fileExistsAtPath:[candidateLegacyPath stringByAppendingPathComponent:@"procursus/.installed_dopamine"]];
                    
                    if (installedDopamine) {
                        // Hopefully all other jailbreaks that use jb-<UUID>?
                        // These checks exist because of dumb users (and jailbreak developers) creating .installed_dopamine on jailbreaks that are NOT dopamine...
                        BOOL installedNekoJB = [[NSFileManager defaultManager] fileExistsAtPath:[candidateLegacyPath stringByAppendingPathComponent:@"procursus/.installed_nekojb"]];
                        BOOL installedDefinitelyNotAGoodName = [[NSFileManager defaultManager] fileExistsAtPath:[candidateLegacyPath stringByAppendingPathComponent:@"procursus/.xia0o0o0o_jb_installed"]];
                        BOOL installedPalera1n = [[NSFileManager defaultManager] fileExistsAtPath:[candidateLegacyPath stringByAppendingPathComponent:@"procursus/.palecursus_strapped"]];
                        if (installedNekoJB || installedPalera1n || installedDefinitelyNotAGoodName) {
                            continue;
                        }
                        
                        randomizedJailbreakPath = candidateLegacyPath;
                        _bootstrapNeedsMigration = YES;
                        break;
                    }
                }
            }
        }
        
        if (randomizedJailbreakPath) {
            NSString *jailbreakRootPath = [randomizedJailbreakPath stringByAppendingPathComponent:@"procursus"];
            if ([[NSFileManager defaultManager] fileExistsAtPath:jailbreakRootPath]) {
                // This attribute serves as the primary source of what the root path is
                // Anything else in the jailbreak will get it from here
                gSystemInfo.jailbreakInfo.rootPath = strdup(jailbreakRootPath.fileSystemRepresentation);
            }
        }
    }
}

- (NSError *)ensureJailbreakRootExists
{
    NSError *error = nil;

    [self locateJailbreakRoot];

    if (!gSystemInfo.jailbreakInfo.rootPath || _bootstrapNeedsMigration) {
        [_bootstrapper ensurePrivatePrebootIsWritable];

        NSString *activePrebootPath = [self activePrebootPath];

        NSString *characterSet = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        NSUInteger stringLen = 6;
        NSMutableString *randomString = [NSMutableString stringWithCapacity:stringLen];
        for (NSUInteger i = 0; i < stringLen; i++) {
            NSUInteger randomIndex = arc4random_uniform((uint32_t)[characterSet length]);
            unichar randomCharacter = [characterSet characterAtIndex:randomIndex];
            [randomString appendFormat:@"%C", randomCharacter];
        }
        
        NSString *randomJailbreakFolderName = [NSString stringWithFormat:@"dopamine-%@", randomString];
        NSString *randomizedJailbreakPath = [activePrebootPath stringByAppendingPathComponent:randomJailbreakFolderName];
        NSString *jailbreakRootPath = [randomizedJailbreakPath stringByAppendingPathComponent:@"procursus"];
        
        if (_bootstrapNeedsMigration) {
            NSString *oldRandomizedJailbreakPath = [[NSString stringWithUTF8String:gSystemInfo.jailbreakInfo.rootPath] stringByDeletingLastPathComponent];
            [[NSFileManager defaultManager] moveItemAtPath:oldRandomizedJailbreakPath toPath:randomizedJailbreakPath error:&error];
        }
        else {
            [[NSFileManager defaultManager] createDirectoryAtPath:randomizedJailbreakPath withIntermediateDirectories:YES attributes:nil error:&error];
        }
        
        if (!error) {
            gSystemInfo.jailbreakInfo.rootPath = strdup(jailbreakRootPath.fileSystemRepresentation);
        }
    }
    
    return error;
}

@end
