package util

class Env {

    private static String mustGetEnv(String envVar) {
        String value = System.getenv(envVar)
        if (!value) {
            throw new RuntimeException(envVar + " must be defined in the env")
        }
        return value
    }

    static int mustGetPort() {
        String portString = mustGetEnv("PORT")
        int port
        try {
            port = Integer.parseInt(portString)
        } catch (NumberFormatException e) {
            throw new RuntimeException("PORT " + portString + " is not a valid number " + e.toString())
        }
        return port
    }

    static String mustGetHostname() {
        return mustGetEnv("HOSTNAME")
    }
}

