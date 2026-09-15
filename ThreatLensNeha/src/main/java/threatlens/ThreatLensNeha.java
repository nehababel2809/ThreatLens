package threatlens;

import java.net.URI;
import java.util.Scanner;
import java.util.regex.Pattern;

public class ThreatLensNeha {

    private static final String[] SUSPICIOUS_KEYWORDS = {
        "login", "verify", "verification", "secure",
        "account", "update", "confirm", "password",
        "bank", "signin", "free"
    };

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        System.out.println("======================================");
        System.out.println("          THREATLENS URL SCANNER      ");
        System.out.println("======================================");

        System.out.print("Enter a URL to analyze: ");
        String url = scanner.nextLine().trim();

        if (url.isEmpty()) {
            System.out.println("Error: URL cannot be empty.");
            scanner.close();
            return;
        }

        analyzeUrl(url);

        scanner.close();
    }

    private static void analyzeUrl(String url) {

        int score = 0;
        StringBuilder findings = new StringBuilder();

        String lower = url.toLowerCase();

        // HTTPS check
        if (!lower.startsWith("https://")) {
            score += 20;
            findings.append("- URL does not use HTTPS (+20)\n");
        } else {
            findings.append("- HTTPS is enabled (0)\n");
        }

        // URL length check
        if (url.length() > 100) {
            score += 15;
            findings.append("- Very long URL (+15)\n");
        } else if (url.length() > 75) {
            score += 8;
            findings.append("- Moderately long URL (+8)\n");
        } else {
            findings.append("- URL length looks normal (0)\n");
        }

        // IP address check
        if (containsIpAddress(url)) {
            score += 25;
            findings.append("- IP address used instead of a normal domain (+25)\n");
        } else {
            findings.append("- No obvious IP-address host (+0)\n");
        }

        // Suspicious keyword check
        int keywordCount = 0;

        for (String keyword : SUSPICIOUS_KEYWORDS) {
            if (lower.contains(keyword)) {
                keywordCount++;
            }
        }

        if (keywordCount >= 3) {
            score += 20;
            findings.append("- Multiple suspicious keywords found ("
                    + keywordCount + ") (+20)\n");
        } else if (keywordCount > 0) {
            score += 8;
            findings.append("- Suspicious keyword(s) found ("
                    + keywordCount + ") (+8)\n");
        } else {
            findings.append("- No common suspicious keywords found (0)\n");
        }

        // @ symbol check
        if (url.contains("@")) {
            score += 15;
            findings.append("- '@' symbol found in URL (+15)\n");
        } else {
            findings.append("- No '@' symbol found (0)\n");
        }

        // Hyphen check
        long hyphens = url.chars()
                .filter(ch -> ch == '-')
                .count();

        if (hyphens >= 4) {
            score += 10;
            findings.append("- Excessive hyphens detected ("
                    + hyphens + ") (+10)\n");
        } else {
            findings.append("- Hyphen usage looks normal (0)\n");
        }

        // Subdomain check
        int subdomainScore = checkSubdomains(url);
        score += subdomainScore;

        if (subdomainScore > 0) {
            findings.append("- Unusually many subdomain levels (+10)\n");
        } else {
            findings.append("- Subdomain structure looks normal (0)\n");
        }

        // Limit score to 100
        score = Math.min(score, 100);

        String risk;

        if (score >= 60) {
            risk = "HIGH RISK";
        } else if (score >= 30) {
            risk = "SUSPICIOUS";
        } else {
            risk = "LOW RISK";
        }

        System.out.println("\n----------- SCAN RESULT -----------");
        System.out.println("URL         : " + url);
        System.out.println("Threat Score: " + score + "/100");
        System.out.println("Risk Level  : " + risk);
        System.out.println("-----------------------------------");

        System.out.println("Findings:");
        System.out.print(findings);

        System.out.println("-----------------------------------");
        System.out.println("Note: This is a rule-based heuristic scanner.");
        System.out.println("It does not guarantee that a URL is safe or malicious.");
    }

    private static boolean containsIpAddress(String url) {

        try {
            URI uri = URI.create(url);
            String host = uri.getHost();

            if (host == null) {
                return false;
            }

            return Pattern.matches(
                    "^(\\d{1,3}\\.){3}\\d{1,3}$",
                    host
            );

        } catch (Exception e) {
            return false;
        }
    }

    private static int checkSubdomains(String url) {

        try {
            URI uri = URI.create(url);
            String host = uri.getHost();

            if (host == null) {
                return 0;
            }

            int dots = host.length()
                    - host.replace(".", "").length();

            return dots >= 4 ? 10 : 0;

        } catch (Exception e) {
            return 0;
        }
    }
}
