require("dotenv").config();

const express = require("express");
const OpenAI = require("openai");
const { GoogleGenAI } = require("@google/genai");
const dns = require("dns").promises;
const net = require("net");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static("public"));

// ==================================================
// DEEPSEEK CLIENT
// ==================================================
const client = new OpenAI({
    apiKey: process.env.DEEPSEEK_API_KEY,
    baseURL: "https://api.deepseek.com"
});

// ==================================================
// GEMINI CLIENT
// ==================================================
const gemini = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY || ""
});

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

// ==================================================
// MESSAGE SCANNER
// ==================================================
app.post("/check-message", async (req, res) => {
    try {
        const message = req.body.message;

        if (!message) {
            return res.status(400).json({
                error: "Message is required."
            });
        }

        const completion = await client.chat.completions.create({
            model: "deepseek-chat",
            messages: [
                {
                    role: "system",
                    content: `
You are ScamGuard AI.

Analyze the user's message and determine whether it is safe,
suspicious, or a scam.

Return ONLY valid JSON in this exact format:

{
  "risk": 0,
  "explanation": "Short explanation of why this message is safe or suspicious."
}

Risk rules:
0-29 = Low risk
30-69 = Suspicious
70-100 = High scam risk

Look for:
- Urgent or threatening language
- Requests for OTP, password or personal information
- Suspicious links
- Requests to send money
- Fake prizes or rewards
- Account blocking threats
- Impersonation
- Unusual payment requests
- Other scam indicators

Do not automatically call a message a scam just because it contains
words such as "OTP", "bank", or "verify". Consider the complete context.
`
                },
                {
                    role: "user",
                    content: message
                }
            ]
        });

        const result = completion.choices[0].message.content;
        const cleanedResult = result
            .replace(/```json/g, "")
            .replace(/```/g, "")
            .trim();

        const data = JSON.parse(cleanedResult);

        res.json({
            risk: Math.max(0, Math.min(100, Number(data.risk))),
            explanation: data.explanation
        });
    } catch (error) {
        console.error("DeepSeek Error:", error);
        res.status(500).json({
            error: "DeepSeek API request failed."
        });
    }
});

// ==================================================
// EMAIL SCANNER
// ==================================================
app.post("/check-email", async (req, res) => {
    try {
        const { sender, subject, body, link } = req.body;

        if (!sender || !subject || !body) {
            return res.status(400).json({
                error: "Sender, subject and email body are required."
            });
        }

        const completion = await client.chat.completions.create({
            model: "deepseek-chat",
            messages: [
                {
                    role: "system",
                    content: `You are ScamGuard AI, an AI assistant that detects scam emails.

Analyze the email and return ONLY valid JSON in this format:
{
  "risk": 0,
  "explanation": "short explanation"
}

The risk must be a number from 0 to 100. Use 0-29 for low risk, 30-69 for suspicious, and 70-100 for high scam risk. Consider urgency, impersonation, requests for credentials or money, suspicious links, threats, and unusual sender details.`
                },
                {
                    role: "user",
                    content: `Sender: ${sender}\nSubject: ${subject}\nEmail body: ${body}\nLink: ${link || "None provided"}`
                }
            ]
        });

        const result = completion.choices?.[0]?.message?.content;
        if (!result) {
            throw new Error("DeepSeek returned an empty response.");
        }

        const data = JSON.parse(
            result.replace(/```json/gi, "").replace(/```/g, "").trim()
        );

        const risk = Number(data.risk);
        if (!Number.isFinite(risk)) {
            throw new Error("DeepSeek returned an invalid risk value.");
        }

        res.json({
            risk: Math.max(0, Math.min(100, risk)),
            explanation: data.explanation || "No explanation received."
        });
    } catch (error) {
        console.error("DeepSeek Email Error:", error);

        const message = error?.status === 401
            ? "DeepSeek rejected the API key. Check DEEPSEEK_API_KEY in .env."
            : error?.status === 429
                ? "DeepSeek rate limit or balance limit reached."
                : "DeepSeek email analysis failed. Check the server log for details.";

        res.status(500).json({ error: message });
    }
});

// ==================================================
// URL SECURITY HELPERS
// ==================================================
function isPrivateIP(ip) {
    if (net.isIPv4(ip)) {
        const parts = ip.split(".").map(Number);
        return (
            parts[0] === 10 ||
            parts[0] === 127 ||
            (parts[0] === 169 && parts[1] === 254) ||
            (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
            (parts[0] === 192 && parts[1] === 168)
        );
    }

    if (net.isIPv6(ip)) {
        const normalized = ip.toLowerCase();
        return (
            normalized === "::1" ||
            normalized.startsWith("fc") ||
            normalized.startsWith("fd") ||
            normalized.startsWith("fe80:")
        );
    }

    return false;
}

async function checkHostnameSafety(hostname) {
    const lowerHost = hostname.toLowerCase();

    if (lowerHost === "localhost" || lowerHost.endsWith(".localhost") || lowerHost.endsWith(".local")) {
        return {
            safe: false,
            reason: "Local/private hostname detected."
        };
    }

    if (net.isIP(lowerHost)) {
        if (isPrivateIP(lowerHost)) {
            return {
                safe: false,
                reason: "Private/internal IP address detected."
            };
        }

        return {
            safe: true,
            resolvedIPs: [lowerHost]
        };
    }

    try {
        const addresses = await dns.lookup(hostname, { all: true });
        const resolvedIPs = addresses.map((item) => item.address);
        const privateAddress = resolvedIPs.find((ip) => isPrivateIP(ip));

        if (privateAddress) {
            return {
                safe: false,
                reason: "Hostname resolves to a private/internal IP address.",
                resolvedIPs
            };
        }

        return {
            safe: true,
            resolvedIPs
        };
    } catch (error) {
        return {
            safe: false,
            reason: "DNS lookup failed or hostname could not be resolved."
        };
    }
}

async function checkVirusTotalURL(inputURL) {
    if (!VIRUSTOTAL_API_KEY) {
        console.warn("⚠️ VirusTotal API key is not configured.");
        return {
            available: false,
            found: false,
            error: "VirusTotal API key is not configured."
        };
    }

    try {
        const urlID = Buffer.from(inputURL)
            .toString("base64")
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");

        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlID}`, {
            method: "GET",
            headers: {
                "x-apikey": VIRUSTOTAL_API_KEY
            }
        });

        if (response.status === 404) {
            return {
                available: true,
                found: false,
                message: "URL is not currently present in the VirusTotal database."
            };
        }

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`VirusTotal API error ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        const attributes = data?.data?.attributes || {};
        const stats = attributes.last_analysis_stats || {};

        return {
            available: true,
            found: true,
            reputation: attributes.reputation ?? 0,
            categories: attributes.categories || {},
            analysisStats: {
                harmless: stats.harmless || 0,
                malicious: stats.malicious || 0,
                suspicious: stats.suspicious || 0,
                undetected: stats.undetected || 0,
                timeout: stats.timeout || 0
            },
            finalURL: attributes.last_final_url || null,
            httpStatus: attributes.last_http_response_code || null,
            timesSubmitted: attributes.times_submitted || 0,
            firstSubmissionDate: attributes.first_submission_date || null,
            lastAnalysisDate: attributes.last_analysis_date || null
        };
    } catch (error) {
        console.error("❌ VirusTotal Error:", error.message);
        return {
            available: false,
            found: false,
            error: "VirusTotal reputation check failed."
        };
    }
}

async function inspectURL(inputURL) {
    const parsed = new URL(inputURL);
    const hostname = parsed.hostname.toLowerCase();
    const signals = [];

    if (parsed.protocol === "https:") {
        signals.push("URL uses HTTPS.");
    } else if (parsed.protocol === "http:") {
        signals.push("URL uses HTTP instead of HTTPS.");
    }

    signals.push(`Hostname: ${hostname}`);

    if (inputURL.length > 150) {
        signals.push("URL is unusually long.");
    }

    const suspiciousHostnamePatterns = [
        /login/i,
        /verify/i,
        /verification/i,
        /secure/i,
        /security/i,
        /account/i,
        /update/i,
        /password/i,
        /wallet/i,
        /payment/i,
        /bank/i,
        /bonus/i,
        /gift/i,
        /prize/i,
        /free/i
    ];

    const hostnameMatches = suspiciousHostnamePatterns.filter((pattern) => pattern.test(hostname));
    if (hostnameMatches.length > 0) {
        signals.push("Hostname contains words commonly used in phishing/social-engineering URLs.");
    }

    if (hostname.includes("@")) {
        signals.push("Hostname contains an @ character.");
    }

    if (hostname.includes("--")) {
        signals.push("Hostname contains repeated hyphens.");
    }

    const hostnameParts = hostname.split(".").filter(Boolean);
    if (hostnameParts.length >= 5) {
        signals.push("URL contains an unusually deep subdomain structure.");
    }

    if (/%[0-9A-F]{2}/i.test(inputURL)) {
        signals.push("URL contains encoded characters.");
    }

    if (net.isIP(hostname)) {
        signals.push("URL uses a raw IP address instead of a normal domain name.");
    }

    const dnsResult = await checkHostnameSafety(hostname);
    if (!dnsResult.safe) {
        signals.push(dnsResult.reason);
    }

    let liveCheck = {
        reachable: false,
        status: null,
        statusText: null,
        finalURL: inputURL,
        redirects: []
    };

    let currentURL = inputURL;

    try {
        for (let i = 0; i < 4; i++) {
            const currentParsed = new URL(currentURL);
            const currentSafety = await checkHostnameSafety(currentParsed.hostname);

            if (!currentSafety.safe) {
                signals.push(`Redirect target blocked: ${currentSafety.reason}`);
                break;
            }

            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 8000);
            let response;

            try {
                response = await fetch(currentURL, {
                    method: "HEAD",
                    redirect: "manual",
                    signal: controller.signal
                });
            } finally {
                clearTimeout(timeout);
            }

            liveCheck.reachable = true;
            liveCheck.status = response.status;
            liveCheck.statusText = response.statusText;

            if (response.status >= 300 && response.status < 400) {
                const location = response.headers.get("location");
                if (!location) break;

                const nextURL = new URL(location, currentURL).toString();
                liveCheck.redirects.push(nextURL);
                signals.push(`Redirect detected to ${nextURL}`);
                currentURL = nextURL;
                continue;
            }

            liveCheck.finalURL = currentURL;
            break;
        }
    } catch (error) {
        liveCheck.reachable = false;
        signals.push("Live server check could not be completed.");
    }

    return {
        originalURL: inputURL,
        hostname,
        protocol: parsed.protocol,
        port: parsed.port || (parsed.protocol === "https:" ? "443" : "80"),
        resolvedIPs: dnsResult.resolvedIPs || [],
        signals,
        liveCheck
    };
}

async function analyzeURLWithGemini(inspection, virusTotal) {
    if (!process.env.GEMINI_API_KEY) {
        throw new Error("GEMINI_API_KEY is not configured in .env");
    }

    const prompt = `
You are ScamGuard AI, a cybersecurity URL risk analyst.

Analyze the URL using ONLY the technical evidence and threat-intelligence evidence supplied below.

Return ONLY valid JSON in exactly this format:
{
  "risk": 0,
  "explanation": "short explanation"
}

Risk rules:
0-29 = low risk
30-69 = suspicious
70-100 = high scam risk

IMPORTANT:
Do not use a fixed/default score.
Base the score on the actual evidence.

Consider:
- HTTPS vs HTTP
- hostname structure
- suspicious hostname words
- unusual subdomains
- raw IP address
- URL length
- encoded characters
- DNS resolution
- private/internal IP
- live server response
- HTTP status
- redirects
- final URL

VirusTotal evidence:
- malicious detections
- suspicious detections
- harmless detections
- reputation
- categories
- submission history

VirusTotal rules:
- If VirusTotal is unavailable, do not treat that as evidence that the URL is safe.
- If the URL is not found in VirusTotal, do not automatically classify it as safe or malicious.
- Multiple malicious detections are strong evidence.
- A suspicious word alone does not prove a URL is malicious.
- Do not claim definite safety or maliciousness unless the evidence supports it.

TECHNICAL EVIDENCE:
Original URL:
${inspection.originalURL}

Hostname:
${inspection.hostname}

Protocol:
${inspection.protocol}

Port:
${inspection.port}

Resolved IP addresses:
${inspection.resolvedIPs.join(", ") || "None"}

Technical signals:
${inspection.signals.join("\n") || "None"}

Live server reachable:
${inspection.liveCheck.reachable}

HTTP status:
${inspection.liveCheck.status || "Unknown"}

HTTP status text:
${inspection.liveCheck.statusText || "Unknown"}

Final URL:
${inspection.liveCheck.finalURL}

Redirects:
${inspection.liveCheck.redirects.join(" -> ") || "None"}

VirusTotal availability:
${virusTotal.available}

VirusTotal found:
${virusTotal.found ?? "Unknown"}

VirusTotal message:
${virusTotal.message || "None"}

VirusTotal reputation:
${virusTotal.reputation ?? "Unknown"}

Malformed or irrelevant VirusTotal fields should be ignored.

VirusTotal malicious detections:
${virusTotal.analysisStats?.malicious ?? "Unknown"}

VirusTotal suspicious detections:
${virusTotal.analysisStats?.suspicious ?? "Unknown"}

VirusTotal harmless detections:
${virusTotal.analysisStats?.harmless ?? "Unknown"}

VirusTotal undetected:
${virusTotal.analysisStats?.undetected ?? "Unknown"}

VirusTotal timeout count:
${virusTotal.analysisStats?.timeout ?? "Unknown"}

VirusTotal times submitted:
${virusTotal.timesSubmitted ?? "Unknown"}

VirusTotal categories:
${JSON.stringify(virusTotal.categories || {})}

VirusTotal final URL:
${virusTotal.finalURL || "Unknown"}

VirusTotal HTTP status:
${virusTotal.httpStatus || "Unknown"}
`;

    const response = await gemini.models.generateContent({
        model: "gemini-3.6-flash",
        contents: prompt
    });

    const text = response.text || response.candidates?.[0]?.content?.parts?.map((part) => part.text).join("") || "";
    const cleaned = text.replace(/```json/gi, "").replace(/```/g, "").trim();
    const data = JSON.parse(cleaned);

    const risk = Number(data.risk);
    if (!Number.isFinite(risk)) {
        throw new Error("Gemini returned an invalid risk value.");
    }

    return {
        risk: Math.max(0, Math.min(100, risk)),
        explanation: data.explanation || "No explanation received."
    };
}

// ==================================================
// URL / LINK SCANNER
// ==================================================
app.post("/check-url", async (req, res) => {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: "URL is required." });
        }

        let parsedURL;
        try {
            parsedURL = new URL(url);
        } catch {
            return res.status(400).json({ error: "Please provide a valid URL." });
        }

        if (parsedURL.protocol !== "http:" && parsedURL.protocol !== "https:") {
            return res.status(400).json({ error: "Only HTTP and HTTPS URLs are supported." });
        }

        console.log("🔗 URL received:", url);

        const inspection = await inspectURL(url);
        console.log("🔎 URL Inspection:", inspection);

        const virusTotal = await checkVirusTotalURL(url);
        console.log("🛡️ VirusTotal Result:", virusTotal);

        const geminiResult = await analyzeURLWithGemini(inspection, virusTotal);

        res.json({
            risk: geminiResult.risk,
            explanation: geminiResult.explanation,
            details: {
                hostname: inspection.hostname,
                protocol: inspection.protocol,
                resolvedIPs: inspection.resolvedIPs,
                liveCheck: inspection.liveCheck,
                signals: inspection.signals,
                virusTotal,
                aiEngine: "Gemini"
            }
        });
    } catch (error) {
        console.error("❌ URL Analysis Error:", error);
        res.status(500).json({
            error: "Dynamic URL analysis failed.",
            details: error.message
        });
    }
});

// ==================================================
// START SERVER
// ==================================================
app.listen(PORT, () => {
    console.log(`🛡️ ScamGuard AI server is running at http://localhost:${PORT}`);
    console.log(`🤖 Gemini AI: ${process.env.GEMINI_API_KEY ? "Configured" : "NOT CONFIGURED"}`);
    console.log(`🧠 DeepSeek AI: ${process.env.DEEPSEEK_API_KEY ? "Configured" : "NOT CONFIGURED"}`);
    console.log(`🛡️ VirusTotal: ${process.env.VIRUSTOTAL_API_KEY ? "Configured" : "Optional / Not configured"}`);
});