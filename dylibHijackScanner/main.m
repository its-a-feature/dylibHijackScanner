//
//  main.m
//  dylibHijackScanner
//
//  Created by Cody Thomas, @its_a_feature_, on 9/1/22.
//

#import <Foundation/Foundation.h>
#include "parseFiles.h"



int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString* header = @"\n"
@"        ______       _ _ _       _   _ _ _            _       \n"
@"        |  _  \\     | (_) |     | | | (_|_)          | |      \n"
@"        | | | |_   _| |_| |__   | |_| |_ _  __ _  ___| | __   \n"
@"        | | | | | | | | | '_ \\  |  _  | | |/ _` |/ __| |/ /   \n"
@"        | |/ /| |_| | | | |_) | | | | | | | (_| | (__|   <    \n"
@"        |___/  \\__, |_|_|_.__/  \\_| |_/_| |\\__,_|\\___|_|\\_\\   \n"
@"                __/ |                  _/ |                   \n"
@"               |___/                  |__/                    \n"
@"         _____                                                \n"
@"        /  ___|                                               \n"
@"        \\ `--.  ___ __ _ _ __  _ __   ___ _ __                \n"
@"         `--. \\/ __/ _` | '_ \\| '_ \\ / _ \\ '__|               \n"
@"        /\\__/ / (_| (_| | | | | | | |  __/ |                  \n"
@"        \\____/ \\___\\__,_|_| |_|_| |_|\\___|_|                  \n"
@"\n";
        printf("%s", [header UTF8String]);
        NSUserDefaults *arguments = [NSUserDefaults standardUserDefaults];
        NSString *path;
        bool displayAll = false;
        NSString* types = @"all";
        NSString* outputFormat = @"string";
        if( [arguments objectForKey:@"path"] ){
            path = [arguments stringForKey:@"path"];
        } else {
            printf("Usage: \n");
            printf("-path {/path/to/application/app | /path/to/folder/with_apps}\n");
            printf("\tRequired\n");
            printf("-displayAll [true|false]\n");
            printf("\tOptional - defaults to false and only shows vulnerable applications\n");
            printf("-types [macho,dylib,bundle,all]\n");
            printf("\tOptional - defaults to 'all' and shows all file types\n");
            printf("\tCan supply multiple types separated via commas\n");
            printf("-outputFormat [string,json,prettyjson]\n");
            printf("\tOptional - defaults to 'string'\n");
            return 0;
        }
        displayAll = [arguments boolForKey:@"displayAll"];
        if( [arguments objectForKey:@"types"] ){
            types = [arguments stringForKey:@"types"];
        }
        if( [arguments objectForKey:@"outputFormat"] ){
            outputFormat = [arguments stringForKey:@"outputFormat"];
        }
        NSMutableArray<fileData*>* allApplications = recursivelyFindFiles(path);
        NSMutableString* displayString = [[NSMutableString alloc] init];
        NSMutableArray* vulnerableApplications = findVulnerablePaths(allApplications, displayAll, types, &displayString);
        NSData* jsonData;
        NSString* finalString;
        if (@available(macOS 10.15, *)) {
            if( [outputFormat isEqualToString:@"prettyjson"] ){
                jsonData = [NSJSONSerialization dataWithJSONObject:vulnerableApplications options:NSJSONWritingSortedKeys|NSJSONWritingPrettyPrinted|NSJSONWritingWithoutEscapingSlashes error:nil];
                finalString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            } else if( [outputFormat isEqualToString:@"json"] ){
                jsonData = [NSJSONSerialization dataWithJSONObject:vulnerableApplications options:NSJSONWritingSortedKeys|NSJSONWritingWithoutEscapingSlashes error:nil];
                finalString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            } else {
                finalString = displayString;
            }
            
            
        } else {
            // Fallback on earlier versions
            if( [outputFormat isEqualToString:@"prettyjson"] ){
                jsonData = [NSJSONSerialization dataWithJSONObject:vulnerableApplications options:NSJSONWritingSortedKeys|NSJSONWritingPrettyPrinted error:nil];
                finalString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            } else if( [outputFormat isEqualToString:@"json"] ){
                jsonData = [NSJSONSerialization dataWithJSONObject:vulnerableApplications options:NSJSONWritingSortedKeys error:nil];
                finalString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            } else {
                finalString = displayString;
            }
        }
        printf("%s\n", [finalString UTF8String]);
    }
    return 0;
}




