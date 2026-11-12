plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.linkguard.blocker"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.linkguard.blocker"
        // 只支持 Android 15（API 35）及以上：用户明确要求的范围
        minSdk = 35
        targetSdk = 35
        versionCode = 24
        versionName = "3.9"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // 用 debug 签名，保证 APK 能直接侧载安装（自用工具，不上商店）
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    // 运行时零依赖：只用 Android 框架自带的组件，APK 尽量小、构建尽量稳
    testImplementation("junit:junit:4.13.2")
}
