//
//  parseFiles.h
//  dylibHijackScanner
//
//  Created by Cody Thomas, @its_a_feature_, on 9/1/22.
//

#ifndef parseFiles_h
#define parseFiles_h

#import "parseHeaders.h"

NSMutableArray<fileData*>* recursivelyFindFiles(NSString* basePath);
fileData* processFile(const char* path);
void fixRPaths(NSMutableArray<fileData*>* allApplications, fileData* currentApplication);
NSMutableArray* findVulnerablePaths(NSMutableArray<fileData*>* allApplications, bool displayAllData, NSString* displayVulnerableTypes, NSMutableString** displayString);
void findNestedLibraryImports(NSMutableArray<fileData*>* allApplications);
void findNestedDylibHijacks(NSMutableArray<fileData*>* allApplications);
bool addElementPreventDuplicates(NSMutableArray* array, NSString* string);
#endif /* parseFiles_h */
