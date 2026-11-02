plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.mosip.nativesso.core"
    compileSdk = 34

    defaultConfig {
        minSdk = 28
        val p = { key: String -> "\"" + (project.findProperty(key) as String) + "\"" }
        buildConfigField("String", "ISSUER", p("nsso.issuer"))
        buildConfigField("String", "SUPER_CLIENT_ID", p("nsso.superClientId"))
        buildConfigField("String", "CHILD_CLIENT_ID", p("nsso.childClientId"))
        buildConfigField("String", "SUPER_REDIRECT_URI", p("nsso.superRedirectUri"))
        buildConfigField("String", "CHILD_REDIRECT_URI", p("nsso.childRedirectUri"))
    }
    buildFeatures {
        aidl = true
        buildConfig = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    api("androidx.browser:browser:1.8.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
