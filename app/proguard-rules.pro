# Room
-keep class androidx.room.** { *; }
-keep @androidx.room.Entity class * { *; }

# Keep data models used for JSON (de)serialization via org.json reflection-free parsing
-keep class com.shieldscan.app.data.model.** { *; }
