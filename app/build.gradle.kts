plugins {
  alias(libs.plugins.android.application)
  alias(libs.plugins.compose.compiler)
  alias(libs.plugins.kotlin.serialization)
  alias(libs.plugins.ksp)
}

fun String.asBuildConfigString(): String = "\"${replace("\\", "\\\\").replace("\"", "\\\"")}\""

android {
    namespace = "com.example.omnirelay"
    compileSdk = 36
    defaultConfig {
        applicationId = "com.example.omnirelay"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
        buildConfigField(
            "String",
            "BACKEND_BASE_URL",
            providers.gradleProperty("OMNIRELAY_BACKEND_URL")
                .orElse("https://relay.example.invalid")
                .get().trimEnd('/').asBuildConfigString()
        )
        buildConfigField("String", "FIREBASE_API_KEY", providers.gradleProperty("OMNIRELAY_FIREBASE_API_KEY").orElse("").get().asBuildConfigString())
        buildConfigField("String", "FIREBASE_APP_ID", providers.gradleProperty("OMNIRELAY_FIREBASE_APP_ID").orElse("").get().asBuildConfigString())
        buildConfigField("String", "FIREBASE_PROJECT_ID", providers.gradleProperty("OMNIRELAY_FIREBASE_PROJECT_ID").orElse("").get().asBuildConfigString())
        buildConfigField("String", "FIREBASE_SENDER_ID", providers.gradleProperty("OMNIRELAY_FIREBASE_SENDER_ID").orElse("").get().asBuildConfigString())
    }

    val releaseKeystore = providers.gradleProperty("OMNIRELAY_KEYSTORE_FILE").orNull
    signingConfigs {
        if (!releaseKeystore.isNullOrBlank()) {
            create("production") {
                storeFile = file(releaseKeystore)
                storePassword = providers.gradleProperty("OMNIRELAY_KEYSTORE_PASSWORD").get()
                keyAlias = providers.gradleProperty("OMNIRELAY_KEY_ALIAS").get()
                keyPassword = providers.gradleProperty("OMNIRELAY_KEY_PASSWORD").get()
            }
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfigs.findByName("production")?.let { signingConfig = it }
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
      compose = true
      aidl = false
      buildConfig = true
      shaders = false
    }

    packaging {
      resources {
        excludes += "/META-INF/{AL2.0,LGPL2.1}"
      }
    }
}

kotlin {
    jvmToolchain(17)
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
  val composeBom = platform(libs.androidx.compose.bom)
  implementation(composeBom)

  // Core Android dependencies
  implementation(libs.androidx.core.ktx)
  implementation(libs.androidx.activity.compose)
  implementation(libs.androidx.fragment.ktx)
  implementation(libs.conscrypt.android)

  // Compose
  implementation(libs.androidx.compose.ui)
  implementation(libs.androidx.compose.material3)
  implementation(libs.androidx.compose.material.icons.extended)
  // Tooling
  debugImplementation(libs.androidx.compose.ui.tooling)
  // Local tests
  testImplementation(libs.junit)

  // Durable messages and reliable background delivery
  implementation(libs.androidx.room.runtime)
  implementation(libs.androidx.room.ktx)
  ksp(libs.androidx.room.compiler)
  implementation(libs.androidx.work.runtime.ktx)
  implementation(libs.okhttp)
  implementation(libs.kotlinx.serialization.json)

  // Internet wake-up and professional VoIP media/platform integration
  implementation(platform(libs.firebase.bom))
  implementation(libs.firebase.messaging)
  implementation(libs.livekit.android)
  implementation(libs.androidx.core.telecom)
}
