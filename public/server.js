require("dotenv").config();

const express = require("express");
const OpenAI = require("openai");
const dns = require("dns").promises;
const net = require("net");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static("public"));


// =========================
// DEEPSEEK CLIENT
// =========================

const client = new OpenAI({
    apiKey: process.env.DEEPSEEK_API_KEY,
    baseURL: "https://api.deepseek.com"
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

    // Block localhost names
    if (
        lowerHost === "localhost" ||
        lowerHost.endsWith(".localhost") ||
        lowerHost.endsWith(".local")
    ) {

        return {
            safe: false,
            reason: "Local/private hostname detected."
        };

    }


    // Direct IP address
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

        const addresses =
            await dns.lookup(
                hostname,
                {
                    all: true
                }
            );


        const resolvedIPs =
            addresses.map(
                item => item.address
            );


        const privateAddress =
            resolvedIPs.find(
                ip => isPrivateIP(ip)
            );


        if (privateAddress) {

            return {
                safe: false,
                reason:
                    "Hostname resolves to a private/internal IP address.",
                resolvedIPs
            };

        }


        return {
            safe: true,
            resolvedIPs
        };

    }

    catch (error) {

        return {
            safe: false,
            reason:
                "DNS lookup failed or hostname could not be resolved."
        };

    }

}


// ==================================================
// LIVE URL INSPECTION
// ==================================================

async function inspectURL(inputURL) {

    const parsed =
        new URL(inputURL);


    const hostname =
        parsed.hostname.toLowerCase();


    const signals = [];


    // -------------------------
    // Protocol
    // -------------------------

    if (parsed.protocol === "https:") {

        signals.push(
            "URL uses HTTPS."
        );

    }

    else if (parsed.protocol === "http:") {

        signals.push(
            "URL uses HTTP instead of HTTPS."
        );

    }


    // -------------------------
    // Hostname
    // -------------------------

    signals.push(
        `Hostname: ${hostname}`
    );


    // -------------------------
    // URL length
    // -------------------------

    if (inputURL.length > 150) {

        signals.push(
            "URL is unusually long."
        );

    }


    // -------------------------
    // Suspicious hostname patterns
    // -------------------------

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


    const hostnameMatches =
        suspiciousHostnamePatterns.filter(
            pattern => pattern.test(hostname)
        );


    if (hostnameMatches.length > 0) {

        signals.push(
            "Hostname contains words commonly used in phishing/social-engineering URLs."
        );

    }


    // -------------------------
    // Suspicious characters
    // -------------------------

    if (hostname.includes("@")) {

        signals.push(
            "Hostname contains an @ character."
        );

    }


    if (hostname.includes("--")) {

        signals.push(
            "Hostname contains repeated hyphens."
        );

    }


    // -------------------------
    // Subdomain depth
    // -------------------------

    const hostnameParts =
        hostname.split(".").filter(Boolean);


    if (hostnameParts.length >= 5) {

        signals.push(
            "URL contains an unusually deep subdomain structure."
        );

    }


    // -------------------------
    // Encoded characters
    // -------------------------

    if (/%[0-9A-F]{2}/i.test(inputURL)) {

        signals.push(
            "URL contains encoded characters."
        );

    }


    // -------------------------
    // IP address
    // -------------------------

    if (net.isIP(hostname)) {

        signals.push(
            "URL uses a raw IP address instead of a normal domain name."
        );

    }


    // -------------------------
    // DNS check
    // -------------------------

    const dnsResult =
        await checkHostnameSafety(hostname);


    if (!dnsResult.safe) {

        signals.push(
            dnsResult.reason
        );

    }


    // ==================================================
    // LIVE SERVER CHECK
    // ==================================================

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

            const currentParsed =
                new URL(currentURL);


            const currentSafety =
                await checkHostnameSafety(
                    currentParsed.hostname
                );


            if (!currentSafety.safe) {

                signals.push(
                    `Redirect target blocked: ${currentSafety.reason}`
                );

                break;
            }


            const controller =
                new AbortController();


            const timeout =
                setTimeout(
                    () => controller.abort(),
                    8000
                );


            let response;


            try {

                response =
                    await fetch(
                        currentURL,
                        {
                            method: "HEAD",
                            redirect: "manual",
                            signal: controller.signal
                        }
                    );

            }

            finally {

                clearTimeout(timeout);

            }


            liveCheck.reachable = true;

            liveCheck.status =
                response.status;

            liveCheck.statusText =
                response.statusText;


            // -------------------------
            // Redirect detected
            // -------------------------

            if (
                response.status >= 300 &&
                response.status < 400
            ) {

                const location =
                    response.headers.get("location");


                if (!location) {

                    break;

                }


                const nextURL =
                    new URL(
                        location,
                        currentURL
                    ).toString();


                liveCheck.redirects.push(
                    nextURL
                );


                signals.push(
                    `Redirect detected to ${nextURL}`
                );


                currentURL =
                    nextURL;

                continue;

            }


            liveCheck.finalURL =
                currentURL;


            break;

        }

    }

    catch (error) {

        liveCheck.reachable = false;

        signals.push(
            "Live server check could not be completed."
        );

    }


    // -------------------------
    // Redirect warning
    // -------------------------

    if (liveCheck.redirects.length >= 2) {

        signals.push(
            "Multiple redirects detected."
        );

    }


    return {

        originalURL: inputURL,

        hostname,

        protocol: parsed.protocol,

        port:
            parsed.port ||
            (parsed.protocol === "https:" ? "443" : "80"),

        resolvedIPs:
            dnsResult.resolvedIPs || [],

        signals,

        liveCheck

    };

}


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


        const completion =
            await client.chat.completions.create({

                model: "deepseek-chat",

                messages: [

                    {
                        role: "system",

                        content: `
You are ScamGuard AI, an AI assistant that detects scam messages.

Analyze the user's message and return ONLY valid JSON:

{
  "risk": number,
  "explanation": "short explanation"
}

Rules:
- risk must be between 0 and 100.
- 0-29 = low risk
- 30-69 = suspicious
- 70-100 = high scam risk

Look for:
- urgency
- OTP/password requests
- suspicious links
- money requests
- fake prizes
- account threats
- impersonation
- phishing
- other scam signals
`
                    },

                    {
                        role: "user",
                        content: message
                    }

                ]

            });


        const result =
            completion.choices?.[0]?.message?.content;


        if (!result) {

            throw new Error(
                "DeepSeek returned an empty response."
            );

        }


        console.log(
            "💬 Message AI Response:",
            result
        );


        const cleanedResult =
            result
                .replace(/```json/gi, "")
                .replace(/```/g, "")
                .trim();


        const data =
            JSON.parse(cleanedResult);


        res.json(data);


    }

    catch (error) {

        console.error(
            "❌ DeepSeek Message Error:",
            error
        );


        res.status(500).json({

            error:
                "DeepSeek message analysis failed."

        });

    }

});


// ==================================================
// EMAIL SCANNER
// ==================================================

app.post("/check-email", async (req, res) => {

    try {

        const {
            sender,
            subject,
            body,
            link
        } = req.body;


        // =========================
        // VALIDATION
        // =========================

        if (!sender || !subject || !body) {

            return res.status(400).json({

                error:
                    "Sender, subject and email body are required."

            });

        }


        console.log("📧 Email received by server:");

        console.log({

            sender,
            subject,
            body,
            link

        });


        // =========================
        // DEEPSEEK EMAIL ANALYSIS
        // =========================

        const completion =
            await client.chat.completions.create({

                model: "deepseek-chat",

                messages: [

                    {

                        role: "system",

                        content: `
You are ScamGuard AI, an AI assistant that detects scam emails.

Analyze the email carefully and return ONLY valid JSON.

Use exactly this format:

{
  "risk": 0,
  "explanation": "short explanation"
}

Rules:

- risk must be a number between 0 and 100.
- 0-29 = low risk.
- 30-69 = suspicious.
- 70-100 = high scam risk.

Analyze all available information:

1. Sender email address
2. Email subject
3. Email body
4. Suspicious link

Look for:

- urgency
- threats
- OTP requests
- password requests
- banking information requests
- money requests
- suspicious links
- fake prizes
- impersonation
- account warnings
- phishing
- unusual sender addresses
- suspicious domains

Important:
Do NOT assume an email is a scam only because it contains a link.

Return ONLY valid JSON.
`

                    },

                    {

                        role: "user",

                        content: `
Sender Email:
${sender}

Email Subject:
${subject}

Email Body:
${body}

Suspicious Link:
${link || "No suspicious link provided"}
`

                    }

                ]

            });


        const result =
            completion.choices?.[0]?.message?.content;


        if (!result) {

            throw new Error(
                "DeepSeek returned an empty email response."
            );

        }


        console.log(
            "📧 Email AI Response:",
            result
        );


        const cleanedResult =
            result
                .replace(/```json/gi, "")
                .replace(/```/g, "")
                .trim();


        const data =
            JSON.parse(cleanedResult);


        if (
            typeof data.risk !== "number" ||
            typeof data.explanation !== "string"
        ) {

            throw new Error(
                "Invalid response returned by DeepSeek."
            );

        }


        const risk =
            Math.max(
                0,
                Math.min(100, data.risk)
            );


        res.json({

            risk: risk,

            explanation:
                data.explanation

        });


    }

    catch (error) {

        console.error(
            "❌ DeepSeek Email Error:",
            error
        );


        res.status(500).json({

            error:
                "DeepSeek email analysis failed."

        });

    }

});


// ==================================================
// URL / LINK SCANNER
// ==================================================

app.post("/check-url", async (req, res) => {

    try {

        const { url } = req.body;


        // =========================
        // VALIDATION
        // =========================

        if (!url) {

            return res.status(400).json({

                error:
                    "URL is required."

            });

        }


        let parsedURL;


        try {

            parsedURL =
                new URL(url);

        }

        catch {

            return res.status(400).json({

                error:
                    "Please provide a valid URL."

            });

        }


        // Only allow HTTP/HTTPS
        if (
            parsedURL.protocol !== "http:" &&
            parsedURL.protocol !== "https:"
        ) {

            return res.status(400).json({

                error:
                    "Only HTTP and HTTPS URLs are supported."

            });

        }


        console.log(
            "🔗 URL received:",
            url
        );


        // =========================
        // LIVE URL INSPECTION
        // =========================

        const inspection =
            await inspectURL(url);


        console.log(
            "🔎 URL Inspection:",
            inspection
        );


        // =========================
        // DEEPSEEK ANALYSIS
        // =========================

        const completion =
            await client.chat.completions.create({

                model: "deepseek-chat",

                messages: [

                    {

                        role: "system",

                        content: `
You are ScamGuard AI, a cybersecurity URL risk analyst.

Analyze a website URL using the REAL technical evidence supplied by the server.

Return ONLY valid JSON:

{
  "risk": number,
  "explanation": "short explanation"
}

Risk rules:

- risk must be between 0 and 100.
- 0-29 = low risk
- 30-69 = suspicious
- 70-100 = high risk

IMPORTANT:

Do NOT use a fixed/default score.

The risk must be based on the actual evidence provided.

Consider:

- HTTPS vs HTTP
- hostname structure
- suspicious words
- unusual subdomains
- raw IP addresses
- URL length
- encoded characters
- DNS resolution
- private/internal IP detection
- live server response
- HTTP status
- redirects
- final URL
- multiple redirects

A suspicious word by itself does NOT prove a website is malicious.

Do not claim that a website is definitely safe or malicious unless the supplied evidence supports that conclusion.

Return ONLY JSON.
`

                    },

                    {

                        role: "user",

                        content: `
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
${inspection.signals.join("\n")}

Live server check:
Reachable: ${inspection.liveCheck.reachable}

HTTP Status:
${inspection.liveCheck.status || "Unknown"}

HTTP Status Text:
${inspection.liveCheck.statusText || "Unknown"}

Final URL:
${inspection.liveCheck.finalURL}

Redirects:
${inspection.liveCheck.redirects.join("\n") || "None"}
`

                    }

                ]

            });


        // =========================
        // GET AI RESULT
        // =========================

        const result =
            completion.choices?.[0]?.message?.content;


        if (!result) {

            throw new Error(
                "DeepSeek returned an empty URL response."
            );

        }


        console.log(
            "🔗 URL AI Response:",
            result
        );


        // =========================
        // CLEAN JSON
        // =========================

        const cleanedResult =
            result
                .replace(/```json/gi, "")
                .replace(/```/g, "")
                .trim();


        const data =
            JSON.parse(cleanedResult);


        // =========================
        // VALIDATE AI RESULT
        // =========================

        if (
            typeof data.risk !== "number" ||
            typeof data.explanation !== "string"
        ) {

            throw new Error(
                "Invalid response returned by DeepSeek."
            );

        }


        // =========================
        // KEEP RISK BETWEEN 0-100
        // =========================

        const risk =
            Math.max(
                0,
                Math.min(
                    100,
                    data.risk
                )
            );


        // =========================
        // SEND RESULT
        // =========================

        res.json({

            risk: risk,

            explanation:
                data.explanation,

            details: {

                hostname:
                    inspection.hostname,

                protocol:
                    inspection.protocol,

                resolvedIPs:
                    inspection.resolvedIPs,

                liveCheck:
                    inspection.liveCheck,

                signals:
                    inspection.signals

            }

        });

    }

    catch (error) {

        console.error(
            "❌ URL Analysis Error:",
            error
        );


        res.status(500).json({

            error:
                "Dynamic URL analysis failed."

        });

    }

});


// ==================================================
// START SERVER
// ==================================================

app.listen(PORT, () => {

    console.log(
        `🛡️ ScamGuard AI server is running at http://localhost:${PORT}`
    );

});