package server;

import java.util.HashMap;
import java.util.Map;

public class UserAuth {
    private static final Map<String, String> users = new HashMap<>();

    static {
        // Hardcoded users (username -> password)
        users.put("amith", "1234");
        users.put("john", "pass");
        users.put("admin", "admin123");
    }

    public static boolean authenticate(String username, String password) {
        return users.containsKey(username) && users.get(username).equals(password);
    }
}
