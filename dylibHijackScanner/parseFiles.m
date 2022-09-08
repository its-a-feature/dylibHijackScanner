//
//  parseFiles.m
//  dylibHijackScanner
//
//  Created by Cody Thomas on 9/1/22.
//

#import <Foundation/Foundation.h>
#import "parseHeaders.h"
#include <mach-o/dyld.h>

fileData* processFile(char* path){
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        NSLog(@"Failed to open file (%s): %d", path, fd);
        return nil;
    }

    struct stat stbuf;
    if (fstat(fd, &stbuf) != 0) {
        close(fd);
        NSLog(@"Failed to stat file (%s)", path);
        return nil;
    }

    /* mmap */
    void *data = mmap(NULL, stbuf.st_size, PROT_READ, MAP_FILE|MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED){
        close(fd);
        //NSLog(@"Failed to map file (%s)", path);
        return nil;
    }

    /* Parse */
    macho_input_t input_file;
    input_file.data = data;
    input_file.length = stbuf.st_size;

    //printf("Parsing: %s\n", path);
    fileData* myFileData = parse_macho(&input_file, path);
    if(myFileData == nil){
        close(fd);
        munmap(data, stbuf.st_size);
        //NSLog(@"Failed to parse macho file (%s)", path);
        return nil;
    }

    munmap(data, stbuf.st_size);
    close(fd);
    return myFileData;
}

bool addElementPreventDuplicates(NSMutableArray* array, NSString* string){
    for(int i = 0; i < [array count]; i++){
        NSString* cur = [array objectAtIndex:i];
        if( [cur isEqualToString:string] ){
            return false;
        }
    }
    [array addObject:string];
    return true;
}
bool addApplicationPreventDuplicates(NSMutableArray* array, fileData* data){
    for(int i = 0; i < [array count]; i++){
        fileData* cur = [array objectAtIndex:i];
        if( [cur.applicationPath isEqualToString:data.applicationPath] ){
            return false;
        }
    }
    [array addObject:data];
    return true;
}


NSMutableArray<fileData*>* recursivelyFindFiles(NSString* basePath){
    NSMutableArray<fileData*>* allApplications = [[NSMutableArray alloc] initWithCapacity:0];
    NSMutableArray* pathsToCheck = [[NSMutableArray alloc] initWithObjects:basePath, nil];
    NSFileManager* fileManager = [NSFileManager defaultManager];
    NSMutableSet* paths = [[NSMutableSet alloc] initWithCapacity:0];
    while( [pathsToCheck count] > 0 ){
        NSString* currentPath = [pathsToCheck objectAtIndex:0];
        [pathsToCheck removeObjectAtIndex:0];
        NSError* err;
        NSDictionary<NSFileAttributeKey, id> * attributes = [fileManager attributesOfItemAtPath:currentPath error:&err];
        if(err != nil){
            NSLog(@"Error getting attributesOfItemAtPath for %@: %@", currentPath, err);
            continue;
        }
        if( [[attributes valueForKey:NSFileType] isEqualToString:NSFileTypeDirectory] ){
            NSArray<NSString *> * files = [fileManager contentsOfDirectoryAtPath:currentPath error:&err];
            if(err != nil){
                NSLog(@"Error getting attributesOfItemAtPath: %@", err);
            }
            for(int i = 0; i < [files count]; i++){
                [pathsToCheck addObject:[[NSString alloc] initWithFormat:@"%@/%@", currentPath, [files objectAtIndex:i] ] ];
            }
        } else {
            // only add macho files
            NSString* symlinkedPath = [currentPath stringByResolvingSymlinksInPath];
            if(![paths containsObject:symlinkedPath]){
                [paths addObject:symlinkedPath];
                fileData* myFileData = processFile([currentPath UTF8String]);
                if(myFileData != nil ){
                    if(!myFileData.platformBinary){
                        // don't bother tracking anything for platform binaries since they won't be vulnerable
                        [allApplications addObject:myFileData];
                    }
                    
                }
            }
            
        }
        
    }
    return allApplications;
    
}

NSMutableArray* recursivelyFindAllImportingRPaths(NSMutableArray<fileData*>* filesThatImportThisFile){
    NSMutableArray<fileData*>* allImportingFiles = [[NSMutableArray alloc] initWithCapacity:0];
    for(int i = 0; i < [filesThatImportThisFile count]; i++){
        // add object
        [allImportingFiles addObject:[filesThatImportThisFile objectAtIndex:i]];
        // add all recursive children of object
        NSMutableArray<fileData*>* nextRecursiveImports = recursivelyFindAllImportingRPaths( [filesThatImportThisFile objectAtIndex:i].filesThatImportThisFile );
        [allImportingFiles addObjectsFromArray:nextRecursiveImports];
    }
    // return results
    return allImportingFiles;
}

void fixRPaths(NSMutableArray<fileData*>* allApplications){
    for(int i = 0; i < [allApplications count]; i++){
        fileData* currentApplication = [allApplications objectAtIndex:i];
        for(int j = 0; j < [currentApplication.rPaths count]; j++){
            NSString* rPath = [currentApplication.rPaths objectAtIndex:j];
            if( [rPath hasPrefix:@"@executable_path"] ){
                NSString* executable_path = [currentApplication.applicationPath stringByDeletingLastPathComponent];
                NSString* strippedPrefix = [rPath stringByReplacingOccurrencesOfString:@"@executable_path" withString:@""];
                NSString* newString = [[NSString alloc] initWithFormat:@"%@%@", executable_path, strippedPrefix];
                addElementPreventDuplicates(currentApplication.fixedRPaths, [newString stringByResolvingSymlinksInPath]);
                addElementPreventDuplicates(currentApplication.fixedRPaths, [newString stringByStandardizingPath]);
            }else if( [rPath hasPrefix:@"@loader_path"] ){
                NSString* strippedPrefix = [rPath stringByReplacingOccurrencesOfString:@"@loader_path" withString:@""];
                NSString* newString = [[NSString alloc] initWithFormat:@"%@%@", [currentApplication.applicationPath stringByDeletingLastPathComponent], strippedPrefix];
                addElementPreventDuplicates(currentApplication.fixedRPaths, [newString stringByResolvingSymlinksInPath]);
                addElementPreventDuplicates(currentApplication.fixedRPaths, [newString stringByStandardizingPath]);
            } else if( [rPath hasPrefix:@"/"] ){
                addElementPreventDuplicates(currentApplication.fixedRPaths, [rPath stringByResolvingSymlinksInPath]);
                addElementPreventDuplicates(currentApplication.fixedRPaths, [rPath stringByStandardizingPath]);
            }
        }
        /*
        if([currentApplication.rPaths count] == 0 ){
            // if there's no LC_RPATH defined, take it to mean the current directory
            NSString* executable_path = [currentApplication.applicationPath stringByDeletingLastPathComponent];
            addElementPreventDuplicates(currentApplication.fixedRPaths, executable_path);
        }
         */
    }
    return;
}

void resolveDylibPaths(NSMutableArray<fileData*>* allApplications){
    NSFileManager* fileManager = [NSFileManager defaultManager];
    for(int i = 0; i < [allApplications count]; i++){
        fileData* currentApplication = [allApplications objectAtIndex:i];
        for(int j = 0; j < [currentApplication.relativeImports count]; j++){
            importData* currentImport = [currentApplication.relativeImports objectAtIndex:j];
            if( ![currentImport.importType isEqualToString:@"LC_ID_DYLIB"]) {
                if( [currentImport.importPath hasPrefix:@"@rpath"]){
                    NSMutableArray<fileData*>* allOtherImporterRPaths = recursivelyFindAllImportingRPaths(currentApplication.filesThatImportThisFile);
                    for(fileData* importerApp in allOtherImporterRPaths){
                        for(NSString* importerAppRPath in importerApp.fixedRPaths){
                            addElementPreventDuplicates(currentApplication.fixedRPaths, importerAppRPath);
                            addElementPreventDuplicates(currentApplication.fixedRPaths, importerAppRPath);
                        }
                    }
                    NSString* strippedPrefix = [currentImport.importPath stringByReplacingOccurrencesOfString:@"@rpath" withString:@""];
                    for(NSString* currentRPath in currentApplication.fixedRPaths){
                        NSString* newString = [[NSString alloc] initWithFormat:@"%@%@", currentRPath, strippedPrefix];
                        NSString* standardizedPath = [newString stringByStandardizingPath];
                        NSString* symlinkPath = [newString stringByResolvingSymlinksInPath];
                        if( ![fileManager fileExistsAtPath:standardizedPath] ){
                            currentApplication.hijackableDirectLoad = true;
                        } else if (![fileManager fileExistsAtPath:symlinkPath] ){
                            currentApplication.hijackableDirectLoad = true;
                        }
                        addElementPreventDuplicates(currentImport.fixedImportPaths, standardizedPath);
                        addElementPreventDuplicates(currentImport.fixedImportPaths, symlinkPath);
                    }
                    
                } else if( [currentImport.importPath hasPrefix:@"@executable_path"] ){
                    NSString* strippedPrefix = [currentImport.importPath stringByReplacingOccurrencesOfString:@"@executable_path" withString:@""];
                    // @executable_path is the path to the executable that's running, not the path where the library is located
                    // @loader_path is the path to where the library being loaded exists
                    NSArray* appPieces = [currentApplication.applicationPath componentsSeparatedByString:@".app"];
                    NSString* executable_path;
                    if( [appPieces count] > 0 ){
                        executable_path = [[NSString alloc] initWithFormat:@"%@.app/Contents/MacOS", [appPieces objectAtIndex:0]];
                    } else {
                        NSLog(@"Failed to find .app in currentApplication.applicationPath");
                        executable_path = [currentApplication.applicationPath stringByDeletingLastPathComponent];
                    }
                    
                    NSString* newString = [[NSString alloc] initWithFormat:@"%@%@", executable_path, strippedPrefix];
                    NSString* standardizedPath = [newString stringByStandardizingPath];
                    NSString* symlinkPath = [newString stringByResolvingSymlinksInPath];
                    if( ![fileManager fileExistsAtPath:standardizedPath] ){
                        currentApplication.hijackableDirectLoad = true;
                    } else if (![fileManager fileExistsAtPath:symlinkPath] ){
                        currentApplication.hijackableDirectLoad = true;
                    }
                    addElementPreventDuplicates(currentImport.fixedImportPaths, standardizedPath);
                    addElementPreventDuplicates(currentImport.fixedImportPaths, symlinkPath);
                }
                
            }
        }
        
    }
    return;
}
void findNestedDylibHijacks(NSMutableArray<fileData*>* allApplications){
    for(int i = 0; i < [allApplications count]; i++){
        fileData* currentApplication = [allApplications objectAtIndex:i];
        for(int j = 0; j < [currentApplication.relativeImports count]; j++){
            importData* currentImport = [currentApplication.relativeImports objectAtIndex:j];
            for(int k = 0; k < [currentImport.fixedImportPaths count]; k++){
                NSString* fullImportPath = [currentImport.fixedImportPaths objectAtIndex:k];
                // now loop through all applications to see if they're marked as hijackable directly or indirectly
                // keep doing this loop until we don't get any changes
                bool madeUpdate = true;
                while(madeUpdate){
                    madeUpdate = false;
                    for(int m = 0; m < [allApplications count]; m++){
                        if( [fullImportPath isEqualToString:[allApplications objectAtIndex:m].applicationPath] ){
                            // found a matching path
                            if([allApplications objectAtIndex:m].hijackableDirectLoad || [allApplications objectAtIndex:m].hijackableIndirectLoad){
                                if(addElementPreventDuplicates(currentApplication.hijackableIndirectLoadLibraries, [allApplications objectAtIndex:m].applicationPath)){
                                    // this means we added a new path to our list of indirect hijackable paths
                                    madeUpdate = true;
                                }
                                currentApplication.hijackableIndirectLoad = true;
                            }
                        }
                    }
                }
            }
        }
        
    }
}
void findNestedLibraryImports(NSMutableArray<fileData*>* allApplications){
    for(int i = 0; i < [allApplications count]; i++){
        fileData* currentApplication = [allApplications objectAtIndex:i];
        for(int j = 0; j < [currentApplication.relativeImports count]; j++){
            importData* currentImport = [currentApplication.relativeImports objectAtIndex:j];
            for(int k = 0; k < [currentImport.fixedImportPaths count]; k++){
                NSString* fullImportPath = [currentImport.fixedImportPaths objectAtIndex:k];
                // now loop through all applications to see if they're marked as hijackable directly or indirectly
                // keep doing this loop until we don't get any changes
                bool madeUpdate = true;
                while(madeUpdate){
                    madeUpdate = false;
                    for(int m = 0; m < [allApplications count]; m++){
                        if( [fullImportPath isEqualToString:[allApplications objectAtIndex:m].applicationPath] ){
                            // found a matching path
                            if(addApplicationPreventDuplicates([allApplications objectAtIndex:m].filesThatImportThisFile, currentApplication)){
                                // this means we added a new path to our list of loadable
                                madeUpdate = true;
                            }
                        }
                    }
                }
            }
        }
    }
}

NSString* getSigningFlagsString(int flags){
    NSMutableString* applicationPrint = [[NSMutableString alloc] initWithFormat:@"Signing Flags: 0x%x(", (unsigned int) flags];
    if(flags & kSecCodeSignatureLibraryValidation){
        [applicationPrint appendFormat:@"library-validation,"];
    }
    if(flags & kSecCodeSignatureRuntime){
        [applicationPrint appendFormat:@"hardened-runtime,"];
    }
    [applicationPrint appendFormat:@")"];
    return applicationPrint;
}
NSString* getFileTypeString(int fileType){
    switch(fileType){
        case MH_EXECUTE:
            return @"Executable";
        case MH_DYLIB:
            return @"Dylib";
        default:
            return [[NSString alloc] initWithFormat:@"%d", fileType];
    }
}

NSMutableArray* findVulnerablePaths(NSMutableArray<fileData*>* allApplications, bool displayAllData){
    NSMutableArray* vulnerablePaths = [[NSMutableArray alloc] initWithCapacity:0];
    NSFileManager* fileManager = [NSFileManager defaultManager];
    if([allApplications count] == 0){
        printf("[-] No valid machO executables or dylibs found\n");
        return vulnerablePaths;
    }
    fixRPaths(allApplications);
    resolveDylibPaths(allApplications);
    findNestedLibraryImports(allApplications);
    resolveDylibPaths(allApplications);
    findNestedDylibHijacks(allApplications);
    
    bool foundVulnerableApp = false;
    int vulnerableCount = 1;
    for(int i = 0; i < [allApplications count]; i++){
        fileData* currentApp = [allApplications objectAtIndex:i];
        if(displayAllData || (currentApp.hijackableEntitlements && (currentApp.hijackableDirectLoad || currentApp.hijackableIndirectLoad))){
            foundVulnerableApp = true;
            NSMutableString* applicationPrint = [[NSMutableString alloc] initWithFormat:@"%d. %s\n",vulnerableCount, [currentApp.applicationPath UTF8String]];
            vulnerableCount++;
            if(currentApp.signingFlags & kSecCodeSignatureRuntime) {
                [applicationPrint appendFormat:@"\t[-] Signed and Hardened Runtime Set: %s\n", [getSigningFlagsString(currentApp.signingFlags) UTF8String]];
                if([currentApp.entitlements count] != 0){
                    [applicationPrint appendFormat:@"\t[+] Entitlements: %@\n", currentApp.entitlements];
                } else {
                    [applicationPrint appendFormat:@"\t[-] No Entitlements\n"];
                }
            } else if( currentApp.signingFlags == 0 ) {
                [applicationPrint appendFormat:@"\t[+] Unsigned: %s\n",  [getSigningFlagsString(currentApp.signingFlags) UTF8String]];
                if([currentApp.entitlements count] != 0){
                    [applicationPrint appendFormat:@"\t[+] Entitlements: %@\n", currentApp.entitlements];
                } else {
                    [applicationPrint appendFormat:@"\t[-] No Entitlements\n"];
                }
            } else {
                [applicationPrint appendFormat:@"\t[+] Signed Hardened Runtime Not Set: %s\n", [getSigningFlagsString(currentApp.signingFlags) UTF8String]];
                if([currentApp.entitlements count] != 0){
                    [applicationPrint appendFormat:@"\t[+] Entitlements: %@\n", currentApp.entitlements];
                } else {
                    [applicationPrint appendFormat:@"\t[-] No Entitlements\n"];
                }
            }
            if(currentApp.hijackableDirectLoad){
                [applicationPrint appendFormat:@"\t[+] Directly Hijackable\n"];
            }
            [applicationPrint appendFormat:@"\t[*] File Type: %s\n", [getFileTypeString(currentApp.fileType) UTF8String]];
            //[applicationPrint appendFormat:@"\t[*] HijackableEntitlements: %d\n", currentApp.hijackableEntitlements];
            //[applicationPrint appendFormat:@"\t[*] HijackableDirectly: %d\n", currentApp.hijackableDirectLoad];
            //[applicationPrint appendFormat:@"\t[*] HijackableIndirectly: %d\n", currentApp.hijackableIndirectLoad];
            //[applicationPrint appendFormat:@"\t[*] Platform Binary: %d\n", currentApp.platformBinary];
            if(currentApp.hijackableIndirectLoad){
                [applicationPrint appendFormat:@"\t[+] Indirectly Hijackable by the following:\n"];
                for(int j = 0; j < [currentApp.hijackableIndirectLoadLibraries count]; j++){
                    [applicationPrint appendFormat:@"\t\t%s\n", [[currentApp.hijackableIndirectLoadLibraries objectAtIndex:j] UTF8String]];
                }
            }
            if( [currentApp.filesThatImportThisFile count] > 0 ){
                [applicationPrint appendFormat:@"\t[*] The following files import this one:\n"];
                for(int j = 0; j < [currentApp.filesThatImportThisFile count]; j++){
                    [applicationPrint appendFormat:@"\t\t[*] %s\n", [[currentApp.filesThatImportThisFile objectAtIndex:j].applicationPath UTF8String]];
                    [applicationPrint appendFormat:@"\t\t[*] With the following RPaths:\n"];
                    for(int k = 0; k < [[currentApp.filesThatImportThisFile objectAtIndex:j].fixedRPaths count]; k++){
                        [applicationPrint appendFormat:@"\t\t\tFixed RPath: %s\n", [[[currentApp.filesThatImportThisFile objectAtIndex:j].fixedRPaths objectAtIndex:k] UTF8String]];
                    }
                }
            }
            
            for(int j = 0; j < [currentApp.rPaths count]; j++){
                [applicationPrint appendFormat:@"\tRPath: %s\n", [[currentApp.rPaths objectAtIndex:j] UTF8String]];
                //printf("\tRPath: %s\n", [[currentApp.rPaths objectAtIndex:j] UTF8String]);
            }
            for(NSString* fixedPath in currentApp.fixedRPaths){
                [applicationPrint appendFormat:@"\t\tFixed RPath: %s\n", [fixedPath UTF8String]];
                //printf("\tFixed RPath: %s\n", [fixedPath UTF8String]);
            }
            for(int j = 0; j < [currentApp.relativeImports count]; j++){
                [applicationPrint appendFormat:@"\t%s -", [[currentApp.relativeImports objectAtIndex:j].importType UTF8String]];
                //printf("\t%s -", [[currentApp.relativeImports objectAtIndex:j].importType UTF8String]);
                [applicationPrint appendFormat:@" %s\n", [[currentApp.relativeImports objectAtIndex:j].importPath UTF8String]];
                //printf(" %s\n", [[currentApp.relativeImports objectAtIndex:j].importPath UTF8String]);
                for(int k = 0; k < [[currentApp.relativeImports objectAtIndex:j].fixedImportPaths count]; k++){
                    NSString* fixedPath = [[currentApp.relativeImports objectAtIndex:j].fixedImportPaths objectAtIndex:k];
                    if( [fileManager fileExistsAtPath:fixedPath] ){
                        [applicationPrint appendFormat:@"\t\t[-] Exists: %s\n", [fixedPath UTF8String]];
                        [applicationPrint appendFormat:@"\t\t\t[-] Min Version: %s, Max Version: %s\n", [[currentApp.relativeImports objectAtIndex:j].compatVersion UTF8String], [[currentApp.relativeImports objectAtIndex:j].currentVersion UTF8String]];
                    } else {
                        [applicationPrint appendFormat:@"\t\t[+] Not Found: %s\n", [fixedPath UTF8String]];
                        [applicationPrint appendFormat:@"\t\t\t[-] Min Version: %s, Max Version: %s\n", [[currentApp.relativeImports objectAtIndex:j].compatVersion UTF8String], [[currentApp.relativeImports objectAtIndex:j].currentVersion UTF8String]];
                    }
                }
            }
            for(int j = 0; j < [currentApp.explicitImports count]; j++){
                [applicationPrint appendFormat:@"\t%s -", [[currentApp.explicitImports objectAtIndex:j].importType UTF8String]];
                //printf("\t%s -", [[currentApp.relativeImports objectAtIndex:j].importType UTF8String]);
                [applicationPrint appendFormat:@" %s\n", [[currentApp.explicitImports objectAtIndex:j].importPath UTF8String]];
                NSString* fixedPath = [currentApp.explicitImports objectAtIndex:j].importPath;
                if (@available(macOS 11.0, *)) {
                    if( _dyld_shared_cache_contains_path([fixedPath UTF8String]) ){
                        [applicationPrint appendFormat:@"\t\t[-] Exists: in dyld_shared_cache\n"];
                    }
                } else {
                    // Fallback on earlier versions
                    if( [fileManager fileExistsAtPath:fixedPath] ){
                        [applicationPrint appendFormat:@"\t\t[-] Exists: %s\n", [fixedPath UTF8String]];
                        [applicationPrint appendFormat:@"\t\t\t[-] Min Version: %s, Max Version: %s\n", [[currentApp.explicitImports objectAtIndex:j].compatVersion UTF8String], [[currentApp.explicitImports objectAtIndex:j].currentVersion UTF8String]];
                    } else {
                        [applicationPrint appendFormat:@"\t\t[+] Not Found: %s\n", [fixedPath UTF8String]];
                        [applicationPrint appendFormat:@"\t\t\t[-] Min Version: %s, Max Version: %s\n", [[currentApp.explicitImports objectAtIndex:j].compatVersion UTF8String], [[currentApp.explicitImports objectAtIndex:j].currentVersion UTF8String]];
                    }
                }
                
            }
            printf("\n\n%s", [applicationPrint UTF8String]);
        }
    }
    if(!foundVulnerableApp){
        printf("[-] Failed to find any vulnerable applications\n");
        printf("\tThere could be vulnerable LC_RPATHs, but none that can load up unsigned libraries\n");
    }
    return vulnerablePaths;
}
