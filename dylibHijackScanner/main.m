//
//  main.m
//  dylibHijackScanner
//
//  Created by Cody Thomas on 9/1/22.
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
        if( [arguments objectForKey:@"path"] ){
            path = [arguments stringForKey:@"path"];
        } else {
            printf("Usage: \n");
            printf("-path {/path/to/application/app | /path/to/folder/with_apps}\n");
            printf("\tRequired\n");
            printf("-displayAll [true|false]\n");
            printf("\tOptional - defaults to false and only shows vulnerable applications\n");
        }
        displayAll = [arguments boolForKey:@"displayAll"];
        NSMutableArray<fileData*>* allApplications = recursivelyFindFiles(path);
        findVulnerablePaths(allApplications, displayAll);
    }
    return 0;
}




