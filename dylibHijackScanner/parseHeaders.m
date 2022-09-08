//
//  parseHeaders.m
//  dylibHijackScanner
//
//  Created by Cody Thomas on 9/1/22.
//

#import <Foundation/Foundation.h>
#import "parseHeaders.h"
// https://gist.github.com/landonf/1046134

@implementation importData
-(id) init {
    if ((self = [super init])) {
        self.importPath = @"";
        self.fixedImportPaths = [[NSMutableArray alloc] initWithCapacity:0];
        self.importType = @"";
        self.currentVersion = @"";
        self.compatVersion = @"";
    }
    return self;
}
@end
@implementation fileData
-(id) init {
    if ((self = [super init])) {
        self.applicationPath = @"";
        self.hijackableDirectLoad = false;
        self.hijackableIndirectLoad = false;
        self.hijackableEntitlements = false;
        self.signingFlags = 0;
        self.fileType = 
        self.platformBinary = false;
        self.hijackableIndirectLoadLibraries = [[NSMutableArray alloc] initWithCapacity:0];
        self.rPaths = [[NSMutableArray alloc] initWithCapacity:0];
        self.fixedRPaths = [[NSMutableArray alloc] initWithCapacity:0];
        self.relativeImports = [[NSMutableArray alloc] initWithCapacity:0];
        self.explicitImports = [[NSMutableArray alloc] initWithCapacity:0];
        self.filesThatImportThisFile = [[NSMutableArray alloc] initWithCapacity:0];
    }
    return self;
}
@end

/* Verify that the given range is within bounds. */
static const void *macho_read (macho_input_t *input, const void *address, size_t length) {
    if ((((uint8_t *) address) - ((uint8_t *) input->data)) + length > input->length) {
        //warnx("Short read parsing Mach-O input");
        return NULL;
    }

    return address;
}

/* Verify that address + offset + length is within bounds. */
static const void *macho_offset (macho_input_t *input, const void *address, size_t offset, size_t length) {
    void *result = ((uint8_t *) address) + offset;
    return macho_read(input, result, length);
}

/* return a human readable formatted version number. the result must be free()'d. */
char *macho_format_dylib_version (uint32_t version) {
    char *result;
    asprintf(&result, "%"PRIu32".%"PRIu32".%"PRIu32, (version >> 16) & 0xFF, (version >> 8) & 0xFF, version & 0xFF);
    return result;
}

/* Some byteswap wrappers */
static uint32_t macho_swap32 (uint32_t input) {
    return OSSwapInt32(input);
}

static uint32_t macho_nswap32(uint32_t input) {
    return input;
}

/* Parse a Mach-O header */
fileData* parse_macho (macho_input_t *input, char* path) {
    /* Read the file type. */
    fileData* myFileData = [[fileData alloc] init];
    NSString* basePath = [[NSString alloc] initWithUTF8String:path];
    myFileData.applicationPath = [basePath stringByResolvingSymlinksInPath];
    
    const uint32_t *magic = macho_read(input, input->data, sizeof(uint32_t));
    if (magic == NULL)
        return nil;

    /* Parse the Mach-O header */
    bool m64 = false;
    bool universal = false;
    uint32_t (*swap32)(uint32_t) = macho_nswap32;

    const struct mach_header *header = NULL;
    const struct mach_header_64 *header64;
    size_t header_size = 0;
    const struct fat_header *fat_header = NULL;

    switch (*magic) {
        case MH_CIGAM:
            swap32 = macho_swap32;
            // Fall-through

        case MH_MAGIC:

            header_size = sizeof(*header);
            header = macho_read(input, input->data, header_size);
            if (header == NULL) {
                return nil;
            }
            //printf("Type: Mach-O 32-bit\n");
            break;


        case MH_CIGAM_64:
            swap32 = macho_swap32;
            // Fall-through

        case MH_MAGIC_64:
            header_size = sizeof(*header64);
            header64 = macho_read(input, input->data, sizeof(*header64));
            if (header64 == NULL)
                return nil;

            /* The 64-bit header is a direct superset of the 32-bit header */
            header = (struct mach_header *) header64;

            //printf("Type: Mach-O 64-bit\n");
            m64 = true;
            break;

        case FAT_CIGAM:
        case FAT_MAGIC:
            fat_header = macho_read(input, input->data, sizeof(*fat_header));
            universal = true;
            //printf("Type: Universal\n");
            break;

        default:
            //NSLog(@"Unknown Mach-O magic: 0x%" PRIx32 "", *magic);
            return nil;
    }

    /* Parse universal file. */
    if (universal) {
        uint32_t nfat = OSSwapBigToHostInt32(fat_header->nfat_arch);
        const struct fat_arch *archs = macho_offset(input, fat_header, sizeof(struct fat_header), sizeof(struct fat_arch));
        if (archs == NULL)
            return nil;

        //printf("Architecture Count: %" PRIu32 "\n", nfat);
        for (uint32_t i = 0; i < nfat; i++) {
            const struct fat_arch *arch = macho_read(input, archs + i, sizeof(struct fat_arch));
            if (arch == NULL)
                return nil;

            /* Fetch a pointer to the architecture's Mach-O header. */
            macho_input_t arch_input;
            arch_input.length = OSSwapBigToHostInt32(arch->size);
            arch_input.data = macho_offset(input, input->data, OSSwapBigToHostInt32(arch->offset), arch_input.length);
            if (arch_input.data == NULL)
                return nil;

            /* Parse the architecture's Mach-O header */
            //printf("\n");
            return parse_macho(&arch_input, path);
            //if (!parse_macho(&arch_input, path))
            //    return nil;
        }
        return nil;
    }

    /* Fetch the arch name */
    const NXArchInfo *archInfo = NXGetArchInfoFromCpuType(swap32(header->cputype), swap32(header->cpusubtype));
    if (archInfo != NULL) {
        //printf("Architecture: %s\n", archInfo->name);
    }
    myFileData.fileType = header->filetype;
    /* Parse the Mach-O load commands */
    const struct load_command *cmd = macho_offset(input, header, header_size, sizeof(struct load_command));
    if (cmd == NULL)
        return nil;
    uint32_t ncmds = swap32(header->ncmds);

    /* Iterate over the load commands */
    bool foundCodeSignature = false;
    for (uint32_t i = 0; i < ncmds; i++) {
        /* Load the full command */
        uint32_t cmdsize = swap32(cmd->cmdsize);
        cmd = macho_read(input, cmd, cmdsize);
        if (cmd == NULL)
            return nil;

        /* Handle known types */
        uint32_t cmd_type = swap32(cmd->cmd);
        importData* myImportData = [[importData alloc] init];
       
        switch (cmd_type) {
            case LC_CODE_SIGNATURE:{
                //NSLog(@"Found code signature for %@\n", myFileData.applicationPath);
                foundCodeSignature = true;
                SecStaticCodeRef staticCode = NULL;
                OSStatus status = SecStaticCodeCreateWithPath( CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, [myFileData.applicationPath UTF8String], myFileData.applicationPath.length, false), 0, &staticCode);
                if(status == 0){
                    CFDictionaryRef codeInfo = NULL;
                    status = SecCodeCopySigningInformation(staticCode,  kSecCSSigningInformation, &codeInfo);
                    
                    if(status == 0){
                        NSDictionary* nsCodeInfo = (__bridge NSDictionary*) codeInfo;
                        //NSLog(@"code info: %@", nsCodeInfo);
                        if(nsCodeInfo[@"flags"]){
                            NSNumber* flags = [nsCodeInfo objectForKey:@"flags"];
                            myFileData.signingFlags = [flags intValue ];
                        }
                        if(nsCodeInfo[(__bridge NSString*)kSecCodeInfoPlatformIdentifier]){
                            myFileData.platformBinary = true;
                            //NSLog(@"platform identifier: %@, %@", [nsCodeInfo objectForKey:(__bridge NSString*)kSecCodeInfoPlatformIdentifier], myFileData.applicationPath);
                            return myFileData;
                        }
                        if(nsCodeInfo[(__bridge NSString*)kSecCodeInfoEntitlementsDict]){
                            myFileData.entitlements = [nsCodeInfo objectForKey:(__bridge NSString*)kSecCodeInfoEntitlementsDict];
                        }
                        if(myFileData.signingFlags != 0){
                            if( myFileData.signingFlags & kSecCodeSignatureRuntime ){
                                // this means we have the hardened runtime
                                if( myFileData.entitlements[@"com.apple.security.cs.allow-unsigned-executable-memory"]){
                                    if( myFileData.entitlements[@"com.apple.security.cs.disable-library-validation"] ){
                                        myFileData.hijackableEntitlements = true;
                                    }
                                }
                            } else if(! (myFileData.signingFlags & kSecCodeSignatureLibraryValidation)){
                                myFileData.hijackableEntitlements = true;
                            } else {
                                myFileData.hijackableEntitlements = true;
                            }
                        }else{
                            // no signing data, so we're hijackable based on entitlements anyway
                            myFileData.hijackableEntitlements = true;
                        }
                    } else {
                        //NSLog(@"Failed to get signing information\n");
                    }
                } else {
                    //NSLog(@"Failed to get code signature\n");
                }
                
                break;
            }
            case LC_RPATH:
                /* Fetch the path */
                if (cmdsize < sizeof(struct rpath_command)) {
                    //warnx("Incorrect cmd size");
                    return nil;
                }

                size_t pathlen = cmdsize - sizeof(struct rpath_command);
                const void *pathptr = macho_offset(input, cmd, sizeof(struct rpath_command), pathlen);
                if (pathptr == NULL)
                    return nil;

                char *path = malloc(pathlen);
                strlcpy(path, pathptr, pathlen);
                [myFileData.rPaths addObject: [[NSString alloc] initWithUTF8String:path]];
                free(path);
                break;
                
            //case LC_ID_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_REEXPORT_DYLIB:
            case LC_LOAD_DYLIB: {
                const struct dylib_command *dylib_cmd = (const struct dylib_command *) cmd;

                /* Extract the install name */
                if (cmdsize < sizeof(struct dylib_command)) {
                    //warnx("Incorrect name size");
                    return nil;
                }

                size_t namelen = cmdsize - sizeof(struct dylib_command);
                const void *nameptr = macho_offset(input, cmd, sizeof(struct dylib_command), namelen);
                if (nameptr == NULL)
                    return nil;

                char *name = malloc(namelen);
                strlcpy(name, nameptr, namelen);

                /* Print the dylib info */
                char *current_version = macho_format_dylib_version(swap32(dylib_cmd->dylib.current_version));
                char *compat_version = macho_format_dylib_version(swap32(dylib_cmd->dylib.compatibility_version));
                myImportData.currentVersion = [[NSString alloc] initWithUTF8String:current_version];
                myImportData.compatVersion = [[NSString alloc] initWithUTF8String:compat_version];
                switch (cmd_type) {
                    case LC_ID_DYLIB:
                        //printf("[dylib] ");
                        myImportData.importType = @"LC_ID_DYLIB";
                        break;
                    case LC_LOAD_WEAK_DYLIB:
                        //printf("[weak] ");
                        myImportData.importType = @"LC_LOAD_WEAK_DYLIB";
                        break;
                    case LC_LOAD_DYLIB:
                        //printf("[load] ");
                        myImportData.importType = @"LC_LOAD_DYLIB";
                        break;
                    case LC_REEXPORT_DYLIB:
                        //printf("[reexport] ");
                        myImportData.importType = @"LC_REEXPORT_DYLIB";
                        break;
                    default:
                        //printf("[%"PRIx32"] ", cmd_type);
                        myImportData.importType = @"UNKNOWN";
                        break;
                }
                myImportData.importPath = [[NSString alloc] initWithUTF8String:name];
                if( [myImportData.importPath hasPrefix:@"/"] ){
                    [myFileData.explicitImports addObject:myImportData];
                } else {
                    [myFileData.relativeImports addObject:myImportData];
                }
                /* This is a dyld library identifier */
                //printf("install_name=%s (compatibility_version=%s, version=%s)\n", name, compat_version, current_version);

                free(name);
                free(current_version);
                free(compat_version);
                break;
            }

            default:
                break;
        }
        /* Load the next command */
        cmd = macho_offset(input, cmd, cmdsize, sizeof(struct load_command));
        if (cmd == NULL)
            return nil;
    }
    if(!foundCodeSignature){
        myFileData.hijackableEntitlements = true;
    }
    return myFileData;
}
