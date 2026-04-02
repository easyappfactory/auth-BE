rootProject.name = "auth-be"

dependencyResolutionManagement {
    repositories {
        mavenLocal()
        mavenCentral()
        maven {
            url = uri("https://maven.pkg.github.com/easyappfactory/shared-libraries")
            credentials {
                username = System.getenv("GITHUB_ACTOR") ?: "easyappfactory"
                password = System.getenv("GITHUB_TOKEN")
            }
            content {
                includeGroup("com.easyapp.factory")
            }
        }
    }
}
