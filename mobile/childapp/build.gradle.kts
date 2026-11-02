import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Both apps MUST be signed with the same certificate: the SSO service is guarded by a
// signature-level permission and a same-signer check. keystore.properties (gitignored) selects a
// shared release key; without it both apps use this machine's debug keystore (also shared).
val vendorKeystore = rootProject.file("keystore.properties").takeIf { it.exists() }?.let { f ->
    Properties().apply { f.inputStream().use { load(it) } }
}

android {
    namespace = "io.mosip.nativesso.childapp"
    compileSdk = 34

    defaultConfig {
        applicationId = "io.mosip.nativesso.childapp"
        minSdk = 28
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    signingConfigs {
        if (vendorKeystore != null) {
            create("vendor") {
                storeFile = file(vendorKeystore.getProperty("storeFile"))
                storePassword = vendorKeystore.getProperty("storePassword")
                keyAlias = vendorKeystore.getProperty("keyAlias")
                keyPassword = vendorKeystore.getProperty("keyPassword")
            }
        }
    }
    buildTypes {
        getByName("debug") {
            if (vendorKeystore != null) signingConfig = signingConfigs.getByName("vendor")
        }
        getByName("release") {
            isMinifyEnabled = false
            if (vendorKeystore != null) signingConfig = signingConfigs.getByName("vendor")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation(project(":nssocore"))
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
