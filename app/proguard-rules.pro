# Keep Kotlin serialization descriptors used by the relay wire models.
-keepattributes *Annotation*,InnerClasses,EnclosingMethod
-if @kotlinx.serialization.Serializable class **
-keep,allowoptimization,allowshrinking,allowobfuscation class <1>$$serializer { *; }
-keepclassmembers class ** {
    *** Companion;
}

# Room and Firebase ship consumer rules; retain the database implementation name.
-keep class * extends androidx.room.RoomDatabase
