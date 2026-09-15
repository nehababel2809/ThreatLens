# ThreatLens

ThreatLens is a Java-based rule-driven URL threat analyzer designed to identify suspicious characteristics in URLs and generate a simple threat score.

## Features

- Checks whether the URL uses HTTPS
- Detects unusually long URLs
- Detects IP addresses used instead of domain names
- Identifies suspicious keywords
- Detects the `@` symbol in URLs
- Checks for excessive hyphens
- Checks for unusually many subdomain levels
- Generates a threat score from 0 to 100
- Classifies URLs as LOW RISK, SUSPICIOUS, or HIGH RISK

## Risk Classification

| Score | Risk Level |
|---|---|
| 0–29 | LOW RISK |
| 30–59 | SUSPICIOUS |
| 60–100 | HIGH RISK |

## Technologies Used

- Java
- Maven
- NetBeans IDE
- Java URI API
- Regular Expressions

## How It Works

The application analyzes a URL using a set of rule-based checks. Each suspicious characteristic adds points to the threat score.

The final score is used to classify the URL into one of three risk levels.

## How to Run

1. Clone or download this repository.
2. Open the project in NetBeans.
3. Build the Maven project.
4. Run `ThreatLensNeha.java`.
5. Enter a URL when prompted.
6. View the threat score and findings.

## Example

```text
URL         : https://www.google.com
Threat Score: 0/100
Risk Level  : LOW RISK
