//
//  parseHeaders.h
//  dylibHijackScanner
//
//  Created by Cody Thomas on 9/1/22.
//

#ifndef parseHeaders_h
#define parseHeaders_h
// https://gist.github.com/landonf/1046134
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <err.h>
#include <string.h>

#include <mach-o/arch.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>
#include <libkern/OSAtomic.h>

typedef struct macho_input {
    const void *data;
    size_t length;
} macho_input_t;

//https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/
typedef struct __BlobIndex {
    uint32_t type;                   /* type of entry */
    uint32_t offset;                 /* offset of entry */
} CS_Blob;

typedef struct __MultiBlob {
    uint32_t magic;                  /* magic number */
    uint32_t length;                 /* total length of SuperBlob */
    uint32_t count;                  /* number of index entries following */
    CS_Blob index[];                 /* (count) entries */
    /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_MultiBlob;


@interface importData : NSObject
@property NSString* importPath;
@property NSMutableArray* fixedImportPaths;
@property NSString* importType;
@property NSString* currentVersion;
@property NSString* compatVersion;
-(id) init;
@end
@interface fileData : NSObject
@property int fileType;
@property NSString* applicationPath;
@property NSDictionary* entitlements;
@property bool hijackableDirectLoad;
@property bool hijackableEntitlements;
@property bool hijackableIndirectLoad;
@property bool platformBinary;
@property int signingFlags;
@property NSMutableArray* hijackableIndirectLoadLibraries;
@property NSMutableArray* rPaths; // raw rpaths: @executable_path/../Frameworks
@property NSMutableArray* fixedRPaths; // fixed rpaths: /Applications/blah/blah/Frameworks
@property NSMutableArray<importData*>* relativeImports; // these use the fixedrpath values
@property NSMutableArray<importData*>* explicitImports;
@property NSMutableArray<fileData*>* filesThatImportThisFile; // libraries that import this file after looking at fixed LC_RPATH entries
-(id) init;
@end

static const void *macho_read (macho_input_t *input, const void *address, size_t length);
static const void *macho_offset (macho_input_t *input, const void *address, size_t offset, size_t length);
char *macho_format_dylib_version (uint32_t version);
static uint32_t macho_swap32 (uint32_t input);
static uint32_t macho_nswap32(uint32_t input);
fileData* parse_macho (macho_input_t *input, char* path);

#endif /* parseHeaders_h */
