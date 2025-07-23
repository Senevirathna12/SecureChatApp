package server;

import java.util.HashMap;

public class UserAuth {
    private static final HashMap<String, String> users = new HashMap<>();

    static {
        users.put("john", "pass");
        users.put("amith", "1234");
        users.put("bob", "abc");
    }

    public static boolean authenticate(String username, String password) {
        return users.containsKey(username) && users.get(username).equals(password);
    }
}
