//
//  parseFiles.h
//  dylibHijackScanner
//
//  Created by Cody Thomas on 9/1/22.
//

#ifndef parseFiles_h
#define parseFiles_h

#import "parseHeaders.h"

NSMutableArray<fileData*>* recursivelyFindFiles(NSString* basePath);
fileData* processFile(char* path);
void fixRPaths(NSMutableArray<fileData*>* allApplications, fileData* currentApplication);
NSMutableArray* findVulnerablePaths(NSMutableArray<fileData*>* allApplications, bool displayAllData);
void findNestedLibraryImports(NSMutableArray<fileData*>* allApplications);
void findNestedDylibHijacks(NSMutableArray<fileData*>* allApplications);
bool addElementPreventDuplicates(NSMutableArray* array, NSString* string);
#endif /* parseFiles_h */
