#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#import <Security/Authorization.h>
#include <libgen.h>

static OSStatus runWithPrivileges(AuthorizationRef authRef, const char *tool, char * const *args) {
    FILE *pipe = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    OSStatus status = AuthorizationExecuteWithPrivileges(authRef, tool, kAuthorizationFlagDefaults, args, &pipe);
#pragma clang diagnostic pop
    if (status != errAuthorizationSuccess) {
        return status;
    }
    // Wait for the child process to finish
    int childStatus = 0;
    pid_t pid = 0;
    int fd = fileno(pipe);
    if (fd != -1) {
        pid = fcntl(fd, F_GETOWN, 0);
    }
    if (pid > 0) {
        waitpid(pid, &childStatus, 0);
    } else {
        // Fallback sleep
        sleep(1);
    }
    return status;
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // The label must match the one in your helper's plist
        CFStringRef label = CFSTR("com.archify.helper");
        OSStatus status = 0;
        AuthorizationRef authRef = NULL;
        status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &authRef);
        if (status != errAuthorizationSuccess) {
            fprintf(stderr, "AuthorizationCreate failed: %d\n", (int)status);
            return 1;
        }

        // -----------------------------------------------------------
        // 1. Copy helper binary & plist to privileged locations
        // -----------------------------------------------------------

        // Determine directory where this installer resides
        char exePath[PATH_MAX] = {0};
        uint32_t size = sizeof(exePath);
        if (_NSGetExecutablePath(exePath, &size) != 0) {
            fprintf(stderr, "Unable to get executable path\n");
            return 1;
        }

        NSString *installerDir = [[[NSString stringWithUTF8String:exePath] stringByDeletingLastPathComponent] stringByStandardizingPath];

        NSString *embeddedHelper = [installerDir stringByAppendingPathComponent:@"com.archify.helper"];
        NSString *embeddedPlist  = [installerDir stringByAppendingPathComponent:@"com.archify.helper.plist"];

        if (![[NSFileManager defaultManager] fileExistsAtPath:embeddedHelper]) {
            fprintf(stderr, "Embedded helper not found at %s\n", [embeddedHelper fileSystemRepresentation]);
            return 1;
        }
        if (![[NSFileManager defaultManager] fileExistsAtPath:embeddedPlist]) {
            fprintf(stderr, "Embedded plist not found at %s\n", [embeddedPlist fileSystemRepresentation]);
            return 1;
        }

        const char *destHelper = "/Library/PrivilegedHelperTools/com.archify.helper";
        const char *destPlist  = "/Library/LaunchDaemons/com.archify.helper.plist";

        // Prepare commands
        char *cpHelperArgs[] = {"-f", (char *)[embeddedHelper fileSystemRepresentation], (char *)destHelper, NULL};
        char *cpPlistArgs[]  = {"-f", (char *)[embeddedPlist fileSystemRepresentation],  (char *)destPlist, NULL};

        status = runWithPrivileges(authRef, "/bin/cp", cpHelperArgs);
        if (status != errAuthorizationSuccess) {
            fprintf(stderr, "Failed to copy helper binary (status %d)\n", status);
            AuthorizationFree(authRef, kAuthorizationFlagDefaults);
            return 2;
        }

        status = runWithPrivileges(authRef, "/bin/cp", cpPlistArgs);
        if (status != errAuthorizationSuccess) {
            fprintf(stderr, "Failed to copy helper plist (status %d)\n", status);
            AuthorizationFree(authRef, kAuthorizationFlagDefaults);
            return 2;
        }

        // Ensure proper ownership & permissions
        char *chownArgsHelper[] = {"root:wheel", (char *)destHelper, NULL};
        char *chownArgsPlist[]  = {"root:wheel", (char *)destPlist, NULL};
        runWithPrivileges(authRef, "/usr/sbin/chown", chownArgsHelper);
        runWithPrivileges(authRef, "/usr/sbin/chown", chownArgsPlist);

        // -----------------------------------------------------------
        // 2. Bless the job
        // -----------------------------------------------------------

        CFErrorRef error = NULL;
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wdeprecated-declarations"
        Boolean result = SMJobBless(kSMDomainSystemLaunchd, label, authRef, &error);
        #pragma clang diagnostic pop
        if (!result) {
            if (error) {
                // Retrieve and print detailed error information
                CFStringRef domain = CFErrorGetDomain(error);
                CFIndex code = CFErrorGetCode(error);
                CFStringRef desc = CFErrorCopyDescription(error);

                char domain_c[256] = {0};
                if (CFStringGetCString(domain, domain_c, sizeof(domain_c), kCFStringEncodingUTF8)) {
                    fprintf(stderr, "SMJobBless failed (domain: %s, code: %ld): ", domain_c, (long)code);
                } else {
                    fprintf(stderr, "SMJobBless failed (domain: <unprintable>, code: %ld): ", (long)code);
                }

                char desc_c[512] = {0};
                if (CFStringGetCString(desc, desc_c, sizeof(desc_c), kCFStringEncodingUTF8)) {
                    fprintf(stderr, "%s\n", desc_c);
                } else {
                    fprintf(stderr, "<unable to retrieve description>\n");
                }

                CFRelease(desc);
                CFRelease(error);
            } else {
                fprintf(stderr, "SMJobBless failed: unknown error\n");
            }
            AuthorizationFree(authRef, kAuthorizationFlagDefaults);
            return 2;
        }
        AuthorizationFree(authRef, kAuthorizationFlagDefaults);
        printf("Helper installed successfully.\n");
    }
    return 0;
} 