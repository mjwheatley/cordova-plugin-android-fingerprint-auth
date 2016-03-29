`meteor add cordova:cordova-plugin-android-fingerprint-auth@file:///Users/mjwheatley/Development/Cordova/cordova-plugin-android-fingerprint-auth`

set compile version and build tools
```
compileSdkVersion 23
buildToolsVersion "23.0.2"
```

add dependencies to build.gradle
```
dependencies {
    compile "com.android.support:support-v4:23.1.0"
    compile "com.android.support:support-v13:23.1.0"
    compile "com.android.support:cardview-v7:23.1.0"
    compile 'com.squareup.dagger:dagger:1.2.2'
    compile 'com.squareup.dagger:dagger-compiler:1.2.2'
    compile 'junit:junit:4.12'
    compile 'org.mockito:mockito-core:1.10.19'
}
```