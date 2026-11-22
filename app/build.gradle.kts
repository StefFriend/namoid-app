plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "it.amico.namoid"
    compileSdk = 34
    defaultConfig {
        applicationId = "it.amico.namoid"
        minSdk = 26
        targetSdk = 34
        versionCode = 20
        versionName = "3.15"
    }
    buildTypes {
        release { isMinifyEnabled = false }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
