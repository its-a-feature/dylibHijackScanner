# dylibHijackScanner

dylibHijackScanner is an ObjectiveC scanner for potential dylib hijacks by reading the machO headers of applications and binaries. This sort of static analysis should _always_ be used in conjunction with dynamic analysis to make sure that additional `@rpath` variables are expanded properly since `@rpath` paths can be based on which application loads up a dylib.

## hijack scan flow

1. Given the path to a .app, folder of .apps, folder of binaries, or a binary, recursively try to find all nested files that contain valid MachO headers.
2. For each valid MachO header, parse out the `LC_RPATH`, `LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`, and `LC_CODE_SIGNATURE` headers. Additionally, get the signing flags (if they exist) and entitlements (if they exist).
4. For each `LC_RPATH`, resolve it to the absolute path on disk.
5. For each `LC_LOAD_DYLIB` and `LC_LOAD_WEAK_DYLIB` with a relative path (i.e. uses `@rpath`), make a list of each possible absolute path locations on disk based on all of the associated `LC_RPATH` values. For each possible location, check if that file exists or not. If it's the first place we look and the file doesn't exist, then we have a potential hijack. If we find one that does exist then one that doesn't, we don't have a potential hijack.
6. Go through all processed files with valid MachO headers, look at each of their absolute path import locations and see if that path matches up with another file with a valid MachO header. This allows us to see which binaries/libraries are importing other ones that we want to process and helps identify other `LC_RPATH` values that we need to leverage when assessing potential hijacks.
7. Repeat step 5, but this time using the additional information from step 6.
8. Loop through all of the files to find potential nested dylib hijacks. If binaryA imports LibraryC and LibraryC exists, then we don't have a direct hijack for binaryA. However, if LibraryC then has its own dylib hijack, then we can indirectly hijack binaryA through LibraryC.
9. List out potential dylib hijacks as ones where there's a direct or indirect hijack and the code signing/entitlements combination would allow malicious, unsigned dylibs to be loaded into memory.

## example
```
./dylibHijackScanner -path "/Applications/Visual Studio Code.app"

        ______       _ _ _       _   _ _ _            _       
        |  _  \     | (_) |     | | | (_|_)          | |      
        | | | |_   _| |_| |__   | |_| |_ _  __ _  ___| | __   
        | | | | | | | | | '_ \  |  _  | | |/ _` |/ __| |/ /   
        | |/ /| |_| | | | |_) | | | | | | | (_| | (__|   <    
        |___/  \__, |_|_|_.__/  \_| |_/_| |\__,_|\___|_|\_\   
                __/ |                  _/ |                   
               |___/                  |__/                    
         _____                                                
        /  ___|                                               
        \ `--.  ___ __ _ _ __  _ __   ___ _ __                
         `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|               
        /\__/ / (_| (_| | | | | | | |  __/ |                  
        \____/ \___\__,_|_| |_|_| |_|\___|_|                  

1. /Applications/Visual Studio Code.app/Contents/MacOS/Electron
    [-] Signed and Hardened Runtime Set: Signing Flags: 0x10000(hardened-runtime,)
    [+] Entitlements: {
    "com.apple.security.automation.apple-events" = 1;
    "com.apple.security.cs.allow-dyld-environment-variables" = 1;
    "com.apple.security.cs.allow-jit" = 1;
    "com.apple.security.cs.allow-unsigned-executable-memory" = 1;
    "com.apple.security.cs.disable-library-validation" = 1;
    "com.apple.security.device.audio-input" = 1;
    "com.apple.security.device.camera" = 1;
}
    [*] File Type: Executable
    [+] Indirectly Hijackable by the following:
        /Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework
    RPath: @executable_path/../Frameworks
        Fixed RPath: /Applications/Visual Studio Code.app/Contents/Frameworks
    LC_LOAD_DYLIB - @rpath/Electron Framework.framework/Electron Framework
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Electron Framework
            [-] Min Version: 0.0.0, Max Version: 0.0.0
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework
            [-] Min Version: 0.0.0, Max Version: 0.0.0
    LC_LOAD_DYLIB - /usr/lib/libSystem.B.dylib
        [-] Exists: in dyld_shared_cache
2. /Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework
    [-] Signed and Hardened Runtime Set: Signing Flags: 0x10000(hardened-runtime,)
    [+] Entitlements: {
    "com.apple.security.automation.apple-events" = 1;
    "com.apple.security.cs.allow-dyld-environment-variables" = 1;
    "com.apple.security.cs.allow-jit" = 1;
    "com.apple.security.cs.allow-unsigned-executable-memory" = 1;
    "com.apple.security.cs.disable-library-validation" = 1;
    "com.apple.security.device.audio-input" = 1;
    "com.apple.security.device.camera" = 1;
}
    [+] Directly Hijackable
    [*] File Type: Dylib
    [*] The following files import this one:
        [*] /Applications/Visual Studio Code.app/Contents/MacOS/Electron
        [*] With the following RPaths:
            Fixed RPath: /Applications/Visual Studio Code.app/Contents/Frameworks
        [*] /Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (GPU).app/Contents/MacOS/Code Helper (GPU)
        [*] With the following RPaths:
            Fixed RPath: /Applications/Visual Studio Code.app/Contents/Frameworks
        [*] /Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper
        [*] With the following RPaths:
            Fixed RPath: /Applications/Visual Studio Code.app/Contents/Frameworks
        [*] /Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Renderer).app/Contents/MacOS/Code Helper (Renderer)
        [*] With the following RPaths:
            Fixed RPath: /Applications/Visual Studio Code.app/Contents/Frameworks
    RPath: @loader_path/Libraries
        Fixed RPath: /Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries
        Fixed RPath: /Applications/Visual Studio Code.app/Contents/Frameworks
    LC_LOAD_DYLIB - @rpath/Squirrel.framework/Squirrel
        [+] Not Found: /Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries/Squirrel.framework/Squirrel
            [-] Min Version: 0.0.0, Max Version: 0.0.0
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/Squirrel.framework/Squirrel
            [-] Min Version: 0.0.0, Max Version: 0.0.0
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/Squirrel.framework/Versions/A/Squirrel
            [-] Min Version: 0.0.0, Max Version: 0.0.0
    LC_LOAD_DYLIB - @rpath/ReactiveObjC.framework/ReactiveObjC
        [+] Not Found: /Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries/ReactiveObjC.framework/ReactiveObjC
            [-] Min Version: 0.0.0, Max Version: 0.0.0
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/ReactiveObjC.framework/ReactiveObjC
            [-] Min Version: 0.0.0, Max Version: 0.0.0
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/ReactiveObjC.framework/Versions/A/ReactiveObjC
            [-] Min Version: 0.0.0, Max Version: 0.0.0
    LC_LOAD_DYLIB - @rpath/Mantle.framework/Mantle
        [+] Not Found: /Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries/Mantle.framework/Mantle
            [-] Min Version: 0.0.0, Max Version: 0.0.0
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/Mantle.framework/Mantle
            [-] Min Version: 0.0.0, Max Version: 0.0.0
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/Mantle.framework/Versions/A/Mantle
            [-] Min Version: 0.0.0, Max Version: 0.0.0
    LC_LOAD_DYLIB - @rpath/libffmpeg.dylib
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries/libffmpeg.dylib
            [-] Min Version: 0.0.0, Max Version: 0.0.0
        [+] Not Found: /Applications/Visual Studio Code.app/Contents/Frameworks/libffmpeg.dylib
            [-] Min Version: 0.0.0, Max Version: 0.0.0
...<snip>...
    LC_LOAD_DYLIB - /usr/lib/libSystem.B.dylib
        [-] Exists: in dyld_shared_cache
3. /Applications/Visual Studio Code.app/Contents/Frameworks/Squirrel.framework/Versions/A/Resources/ShipIt
    [-] Signed and Hardened Runtime Set: Signing Flags: 0x10000(hardened-runtime,)
    [+] Entitlements: {
    "com.apple.security.automation.apple-events" = 1;
    "com.apple.security.cs.allow-dyld-environment-variables" = 1;
    "com.apple.security.cs.allow-jit" = 1;
    "com.apple.security.cs.allow-unsigned-executable-memory" = 1;
    "com.apple.security.cs.disable-library-validation" = 1;
    "com.apple.security.device.audio-input" = 1;
    "com.apple.security.device.camera" = 1;
}
    [+] Directly Hijackable
    [*] File Type: Executable
    RPath: @executable_path/../..
    RPath: @executable_path/../../../..
        Fixed RPath: /Applications/Visual Studio Code.app/Contents/Frameworks/Squirrel.framework/Versions
        Fixed RPath: /Applications/Visual Studio Code.app/Contents/Frameworks
    LC_LOAD_DYLIB - @rpath/Mantle.framework/Mantle
        [+] Not Found: /Applications/Visual Studio Code.app/Contents/Frameworks/Squirrel.framework/Versions/Mantle.framework/Mantle
            [-] Min Version: 0.0.0, Max Version: 0.0.0
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/Mantle.framework/Mantle
            [-] Min Version: 0.0.0, Max Version: 0.0.0
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/Mantle.framework/Versions/A/Mantle
            [-] Min Version: 0.0.0, Max Version: 0.0.0
    LC_LOAD_DYLIB - @rpath/ReactiveObjC.framework/ReactiveObjC
        [+] Not Found: /Applications/Visual Studio Code.app/Contents/Frameworks/Squirrel.framework/Versions/ReactiveObjC.framework/ReactiveObjC
            [-] Min Version: 0.0.0, Max Version: 0.0.0
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/ReactiveObjC.framework/ReactiveObjC
            [-] Min Version: 0.0.0, Max Version: 0.0.0
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/ReactiveObjC.framework/Versions/A/ReactiveObjC
            [-] Min Version: 0.0.0, Max Version: 0.0.0
    LC_LOAD_DYLIB - /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit
        [-] Exists: in dyld_shared_cache
    LC_LOAD_DYLIB - /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
        [-] Exists: in dyld_shared_cache
    LC_LOAD_DYLIB - /usr/lib/libobjc.A.dylib
        [-] Exists: in dyld_shared_cache
    LC_LOAD_DYLIB - /System/Library/Frameworks/Foundation.framework/Versions/C/Foundation
        [-] Exists: in dyld_shared_cache
    LC_LOAD_DYLIB - /System/Library/Frameworks/IOKit.framework/Versions/A/IOKit
        [-] Exists: in dyld_shared_cache
    LC_LOAD_DYLIB - /System/Library/Frameworks/Security.framework/Versions/A/Security
        [-] Exists: in dyld_shared_cache
    LC_LOAD_DYLIB - /usr/lib/libSystem.B.dylib
        [-] Exists: in dyld_shared_cache
4. /Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper
    [-] Signed and Hardened Runtime Set: Signing Flags: 0x10000(hardened-runtime,)
    [+] Entitlements: {
    "com.apple.security.automation.apple-events" = 1;
    "com.apple.security.cs.allow-dyld-environment-variables" = 1;
    "com.apple.security.cs.allow-jit" = 1;
    "com.apple.security.cs.allow-unsigned-executable-memory" = 1;
    "com.apple.security.cs.disable-library-validation" = 1;
    "com.apple.security.device.audio-input" = 1;
    "com.apple.security.device.camera" = 1;
}
    [*] File Type: Executable
    [+] Indirectly Hijackable by the following:
        /Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework
    RPath: @executable_path/../../..
        Fixed RPath: /Applications/Visual Studio Code.app/Contents/Frameworks
    LC_LOAD_DYLIB - @rpath/Electron Framework.framework/Electron Framework
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Electron Framework
            [-] Min Version: 0.0.0, Max Version: 0.0.0
        [-] Exists: /Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework
            [-] Min Version: 0.0.0, Max Version: 0.0.0
    LC_LOAD_DYLIB - /usr/lib/libsandbox.1.dylib
        [-] Exists: in dyld_shared_cache
    LC_LOAD_DYLIB - /usr/lib/libSystem.B.dylib
        [-] Exists: in dyld_shared_cache
```

## Options
```
./dylibHijackScanner 

        ______       _ _ _       _   _ _ _            _       
        |  _  \     | (_) |     | | | (_|_)          | |      
        | | | |_   _| |_| |__   | |_| |_ _  __ _  ___| | __   
        | | | | | | | | | '_ \  |  _  | | |/ _` |/ __| |/ /   
        | |/ /| |_| | | | |_) | | | | | | | (_| | (__|   <    
        |___/  \__, |_|_|_.__/  \_| |_/_| |\__,_|\___|_|\_\   
                __/ |                  _/ |                   
               |___/                  |__/                    
         _____                                                
        /  ___|                                               
        \ `--.  ___ __ _ _ __  _ __   ___ _ __                
         `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|               
        /\__/ / (_| (_| | | | | | | |  __/ |                  
        \____/ \___\__,_|_| |_|_| |_|\___|_|                  

Usage: 
-path {/path/to/application/app | /path/to/folder/with_apps}
    Required
-displayAll [true|false]
    Optional - defaults to false and only shows vulnerable applications
-types [macho,dylib,bundle,all]
    Optional - defaults to 'all' and shows all file types
    Can supply multiple types separated via commas
-outputFormat [string,json,prettyjson]
    Optional - defaults to 'string'
```
