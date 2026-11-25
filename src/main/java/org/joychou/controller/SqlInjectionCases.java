package org.joychou.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * SQL injection test cases. Each handler holds one case, named in the comment
 * above it. Cases marked EXPLOITABLE can be attacked; cases marked SAFE build
 * the query the same way but the value cannot carry SQL.
 */
@RestController
public class SqlInjectionCases {

    private static final Set<String> SORT_COLUMNS = Set.of("id", "username", "created_at");

    @Autowired
    private DataSource dataSource;

    private List<String> run(String sql) throws SQLException {
        List<String> rows = new ArrayList<>();
        try (Connection conn = dataSource.getConnection();
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) {
                rows.add(rs.getString(1));
            }
        }
        return rows;
    }

    // EXPLOITABLE 1: request parameter concatenated into a WHERE clause
    @GetMapping("/sqli/user")
    public List<String> userByName(@RequestParam String username) throws SQLException {
        String sql = "SELECT username FROM users WHERE username = '" + username + "'";
        return run(sql);
    }

    // EXPLOITABLE 2: request parameter concatenated into ORDER BY, no allowlist
    @GetMapping("/sqli/sorted")
    public List<String> sorted(@RequestParam String column) throws SQLException {
        String sql = "SELECT username FROM users ORDER BY " + column;
        return run(sql);
    }

    // EXPLOITABLE 3: request parameter concatenated into a LIKE search
    @GetMapping("/sqli/search")
    public List<String> search(@RequestParam String term) throws SQLException {
        String sql = "SELECT username FROM users WHERE username LIKE '%" + term + "%'";
        return run(sql);
    }

    // EXPLOITABLE 4: request parameter concatenated into a DELETE statement
    @GetMapping("/sqli/remove")
    public List<String> remove(@RequestParam String name) throws SQLException {
        String sql = "DELETE FROM users WHERE username = '" + name + "'";
        return run(sql);
    }

    // SAFE 1: ORDER BY column is checked against a fixed allowlist first
    @GetMapping("/sqli/sorted-safe")
    public List<String> sortedSafe(@RequestParam String column) throws SQLException {
        if (!SORT_COLUMNS.contains(column)) {
            throw new IllegalArgumentException("unsupported column");
        }
        String sql = "SELECT username FROM users ORDER BY " + column;
        return run(sql);
    }

    // SAFE 2: the id is parsed to an int, so only digits reach the query
    @GetMapping("/sqli/user-by-id")
    public List<String> userById(@RequestParam String id) throws SQLException {
        int userId = Integer.parseInt(id);
        String sql = "SELECT username FROM users WHERE id = " + userId;
        return run(sql);
    }

    // SAFE 3: the value is stripped to letters and digits before it is used
    @GetMapping("/sqli/search-safe")
    public List<String> searchSafe(@RequestParam String term) throws SQLException {
        String clean = term.replaceAll("[^A-Za-z0-9]", "");
        String sql = "SELECT username FROM users WHERE username LIKE '%" + clean + "%'";
        return run(sql);
    }

    // SAFE 4: the limit is a validated number clamped to a range
    @GetMapping("/sqli/top")
    public List<String> top(@RequestParam String count) throws SQLException {
        int limit = Math.max(1, Math.min(100, Integer.parseInt(count)));
        String sql = "SELECT username FROM users LIMIT " + limit;
        return run(sql);
    }
}
