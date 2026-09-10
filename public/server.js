require("dotenv").config();

const express = require("express");
const OpenAI = require("openai");
const { GoogleGenAI } = require("@google/genai");
const dns = require("dns").promises;
const net = require("net");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "1mb" }));
app.use(express.static("public"));


// ==================================================
// API CLIENTS
// ==================================================

const client = new OpenAI({
    apiKey: process.env.DEEPSEEK_API_KEY,
    baseURL: "https://api.deepseek.com"
});

const gemini = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY
});

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;


// ==================================================
// GENERAL HELPERS
// ==================================================

function clampRisk(value) {

    const number = Number(value);

    if (!Number.isFinite(number)) {
        return 0;
    }

    return Math.max(
        0,
        Math.min(
            100,
            Math.round(number)
        )
    );
}


function getRiskLevel(score) {

    if (score >= 70) {
        return "HIGH RISK";
    }

    if (score >= 30) {
        return "SUSPICIOUS";
    }

    return "LOW RISK";
}


function cleanJSON(text) {

    if (!text || typeof text !== "string") {
        throw new Error(
            "AI returned an empty response."
        );
    }

    return text
        .replace(/```json/gi, "")
        .replace(/```/g, "")
        .trim();
}


function safeJSONParse(text) {

    const cleaned = cleanJSON(text);

    try {

        return JSON.parse(cleaned);

    } catch {

        throw new Error(
            "AI returned invalid JSON."
        );
    }
}


// ==================================================
// TIMEOUT HELPER
// ==================================================

function withTimeout(
    promise,
    milliseconds,
    errorMessage
) {

    let timeoutId;

    const timeoutPromise =
        new Promise((_, reject) => {

            timeoutId = setTimeout(
                () => {

                    reject(
                        new Error(
                            errorMessage
                        )
                    );

                },
                milliseconds
            );

        });


    return Promise.race([
        promise,
        timeoutPromise
    ]).finally(() => {

        clearTimeout(timeoutId);

    });
}


// ==================================================
// IP SECURITY
// ==================================================

function isPrivateIP(ip) {

    if (net.isIPv4(ip)) {

        const parts =
            ip.split(".").map(Number);

        const [a, b, c, d] =
            parts;

        return (

            // 10.0.0.0/8
            a === 10 ||

            // 127.0.0.0/8
            a === 127 ||

            // 169.254.0.0/16
            (a === 169 && b === 254) ||

            // 172.16.0.0/12
            (a === 172 && b >= 16 && b <= 31) ||

            // 192.168.0.0/16
            (a === 192 && b === 168) ||

            // 100.64.0.0/10
            (a === 100 && b >= 64 && b <= 127) ||

            // 0.0.0.0/8
            a === 0 ||

            // Broadcast
            (
                a === 255 &&
                b === 255 &&
                c === 255 &&
                d === 255
            )

        );
    }


    if (net.isIPv6(ip)) {

        const normalized =
            ip.toLowerCase();

        return (

            normalized === "::1" ||

            normalized === "::" ||

            normalized.startsWith("fc") ||

            normalized.startsWith("fd") ||

            normalized.startsWith("fe80:")

        );
    }


    return false;
}


// ==================================================
// DNS HOSTNAME SAFETY
// ==================================================

async function checkHostnameSafety(hostname) {

    const lowerHost =
        hostname.toLowerCase();


    if (
        lowerHost === "localhost" ||
        lowerHost.endsWith(".localhost") ||
        lowerHost.endsWith(".local")
    ) {

        return {

            safe: false,

            reason:
                "Local/private hostname detected.",

            resolvedIPs: []

        };
    }


    if (net.isIP(lowerHost)) {

        if (isPrivateIP(lowerHost)) {

            return {

                safe: false,

                reason:
                    "Private/internal IP address detected.",

                resolvedIPs: [
                    lowerHost
                ]

            };
        }


        return {

            safe: true,

            resolvedIPs: [
                lowerHost
            ]

        };
    }


    try {

        // DNS lookup is also time-limited
        const addresses =
            await withTimeout(
                dns.lookup(
                    hostname,
                    {
                        all: true,
                        verbatim: true
                    }
                ),
                2500,
                "DNS lookup timed out."
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

    } catch (error) {

        return {

            safe: false,

            reason:
                error.message ===
                "DNS lookup timed out."
                    ? "DNS lookup timed out."
                    : "DNS lookup failed or hostname could not be resolved.",

            resolvedIPs: []

        };
    }
}


// ==================================================
// URL NORMALIZATION
// ==================================================

function normalizeURL(input) {

    const trimmed =
        String(input || "").trim();


    if (!trimmed) {

        throw new Error(
            "URL is required."
        );
    }


    let url = trimmed;


    // Allow google.com without protocol.
    if (!/^https?:\/\//i.test(url)) {

        url =
            `https://${url}`;

    }


    const parsed =
        new URL(url);


    if (
        parsed.protocol !== "http:" &&
        parsed.protocol !== "https:"
    ) {

        throw new Error(
            "Only HTTP and HTTPS URLs are supported."
        );
    }


    return parsed.toString();
}


// ==================================================
// VIRUSTOTAL
// ==================================================

async function checkVirusTotalURL(inputURL) {

    if (!VIRUSTOTAL_API_KEY) {

        console.warn(
            "⚠️ VirusTotal API key is not configured."
        );

        return {

            available: false,

            found: false,

            error:
                "VirusTotal API key is not configured."

        };
    }


    try {

        const urlID =
            Buffer
                .from(inputURL)
                .toString("base64")
                .replace(/\+/g, "-")
                .replace(/\//g, "_")
                .replace(/=+$/, "");


        const controller =
            new AbortController();


        const timeout =
            setTimeout(
                () => controller.abort(),
                3000
            );


        let response;


        try {

            response =
                await fetch(
                    `https://www.virustotal.com/api/v3/urls/${urlID}`,
                    {
                        method: "GET",

                        headers: {

                            "x-apikey":
                                VIRUSTOTAL_API_KEY,

                            "accept":
                                "application/json"

                        },

                        signal:
                            controller.signal

                    }
                );

        } finally {

            clearTimeout(timeout);

        }


        if (response.status === 404) {

            return {

                available: true,

                found: false,

                message:
                    "URL is not currently present in the VirusTotal database."

            };
        }


        if (!response.ok) {

            throw new Error(
                `VirusTotal API error ${response.status}`
            );
        }


        const data =
            await response.json();


        const attributes =
            data?.data?.attributes || {};


        const stats =
            attributes.last_analysis_stats || {};


        return {

            available: true,

            found: true,

            reputation:
                attributes.reputation ?? 0,

            categories:
                attributes.categories || {},

            analysisStats: {

                harmless:
                    stats.harmless || 0,

                malicious:
                    stats.malicious || 0,

                suspicious:
                    stats.suspicious || 0,

                undetected:
                    stats.undetected || 0,

                timeout:
                    stats.timeout || 0

            },

            finalURL:
                attributes.last_final_url || null,

            httpStatus:
                attributes.last_http_response_code || null,

            timesSubmitted:
                attributes.times_submitted || 0,

            firstSubmissionDate:
                attributes.first_submission_date || null,

            lastAnalysisDate:
                attributes.last_analysis_date || null

        };

    } catch (error) {

        console.error(
            "❌ VirusTotal Error:",
            error.message
        );


        return {

            available: false,

            found: false,

            error:
                error.name === "AbortError"
                    ? "VirusTotal request timed out."
                    : "VirusTotal reputation check failed."

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


    // ==================================================
    // BASIC URL INFORMATION
    // ==================================================

    if (parsed.protocol === "https:") {

        signals.push(
            "URL uses HTTPS."
        );

    } else {

        signals.push(
            "URL uses HTTP instead of HTTPS."
        );
    }


    signals.push(
        `Hostname: ${hostname}`
    );


    // ==================================================
    // URL LENGTH
    // ==================================================

    if (inputURL.length > 150) {

        signals.push(
            "URL is unusually long."
        );
    }


    // ==================================================
    // SUSPICIOUS HOSTNAME WORDS
    // ==================================================

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
            pattern =>
                pattern.test(hostname)
        );


    if (hostnameMatches.length > 0) {

        signals.push(
            "Hostname contains words commonly used in phishing or social-engineering URLs."
        );
    }


    // ==================================================
    // SUSPICIOUS CHARACTERS
    // ==================================================

    if (hostname.includes("--")) {

        signals.push(
            "Hostname contains repeated hyphens."
        );
    }


    // ==================================================
    // SUBDOMAIN DEPTH
    // ==================================================

    const hostnameParts =
        hostname
            .split(".")
            .filter(Boolean);


    if (hostnameParts.length >= 5) {

        signals.push(
            "URL contains an unusually deep subdomain structure."
        );
    }


    // ==================================================
    // ENCODED CHARACTERS
    // ==================================================

    if (/%[0-9A-F]{2}/i.test(inputURL)) {

        signals.push(
            "URL contains encoded characters."
        );
    }


    // ==================================================
    // RAW IP
    // ==================================================

    if (net.isIP(hostname)) {

        signals.push(
            "URL uses a raw IP address instead of a normal domain name."
        );
    }


    // ==================================================
    // DNS
    // ==================================================

    const dnsCache =
        new Map();


    async function getCachedSafety(
        targetHostname
    ) {

        const host =
            targetHostname.toLowerCase();


        if (dnsCache.has(host)) {

            return dnsCache.get(host);

        }


        const promise =
            checkHostnameSafety(host);


        dnsCache.set(
            host,
            promise
        );


        return promise;
    }


    const dnsResult =
        await getCachedSafety(hostname);


    if (!dnsResult.safe) {

        signals.push(
            dnsResult.reason
        );
    }


    // ==================================================
    // LIVE SERVER CHECK
    // ==================================================

    const liveCheck = {

        reachable: false,

        status: null,

        statusText: null,

        finalURL: inputURL,

        redirects: []

    };


    let currentURL =
        inputURL;


    try {

        // Maximum 2 redirects for speed.
        for (let i = 0; i < 3; i++) {

            const currentParsed =
                new URL(currentURL);


            let currentSafety;


            // Re-use first DNS result instead
            // of performing the same DNS lookup again.
            if (
                currentParsed.hostname.toLowerCase() ===
                hostname
            ) {

                currentSafety =
                    dnsResult;

            } else {

                currentSafety =
                    await getCachedSafety(
                        currentParsed.hostname
                    );

            }


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
                    3000
                );


            let response;


            try {

                // HEAD is fast and does not download page content.
                response =
                    await fetch(
                        currentURL,
                        {

                            method: "HEAD",

                            redirect: "manual",

                            signal:
                                controller.signal,

                            headers: {

                                "User-Agent":
                                    "ScamGuard-AI-URL-Scanner/1.0"

                            }

                        }
                    );

            } finally {

                clearTimeout(timeout);

            }


            liveCheck.reachable =
                true;


            liveCheck.status =
                response.status;


            liveCheck.statusText =
                response.statusText;


            if (
                response.status >= 300 &&
                response.status < 400
            ) {

                const location =
                    response.headers.get(
                        "location"
                    );


                if (!location) {

                    liveCheck.finalURL =
                        currentURL;

                    break;

                }


                let nextURL;


                try {

                    nextURL =
                        new URL(
                            location,
                            currentURL
                        ).toString();

                } catch {

                    signals.push(
                        "Invalid redirect target detected."
                    );

                    break;
                }


                const nextParsed =
                    new URL(nextURL);


                const nextSafety =
                    await getCachedSafety(
                        nextParsed.hostname
                    );


                if (!nextSafety.safe) {

                    signals.push(
                        `Redirect target blocked: ${nextSafety.reason}`
                    );

                    break;
                }


                liveCheck.redirects.push(
                    nextURL
                );


                currentURL =
                    nextURL;


                continue;
            }


            liveCheck.finalURL =
                currentURL;


            break;
        }

    } catch (error) {

        liveCheck.reachable =
            false;


        if (
            error.name === "AbortError"
        ) {

            signals.push(
                "Live server check timed out."
            );

        } else {

            signals.push(
                "Live server check could not be completed."
            );

        }
    }


    if (
        liveCheck.redirects.length >= 2
    ) {

        signals.push(
            "Multiple redirects detected."
        );
    }


    return {

        originalURL:
            inputURL,

        hostname,

        protocol:
            parsed.protocol,

        port:
            parsed.port ||
            (
                parsed.protocol === "https:"
                    ? "443"
                    : "80"
            ),

        resolvedIPs:
            dnsResult.resolvedIPs || [],

        signals,

        liveCheck

    };
}


// ==================================================
// SCAMGUARD RISK ENGINE
// ==================================================

function calculateURLRisk(
    inspection,
    virusTotal
) {

    let score = 0;

    const reasons = [];


    // ==================================================
    // TECHNICAL SIGNALS
    // ==================================================

    if (inspection.protocol === "http:") {

        score += 10;

        reasons.push(
            "URL uses HTTP instead of HTTPS."
        );
    }


    if (net.isIP(inspection.hostname)) {

        score += 15;

        reasons.push(
            "URL uses a raw IP address."
        );
    }


    if (
        inspection.signals.some(
            signal =>
                signal
                    .toLowerCase()
                    .includes("phishing")
        )
    ) {

        score += 10;

        reasons.push(
            "Hostname contains words commonly associated with phishing."
        );
    }


    if (
        inspection.signals.some(
            signal =>
                signal
                    .toLowerCase()
                    .includes("unusually deep")
        )
    ) {

        score += 10;

        reasons.push(
            "URL has an unusually deep subdomain structure."
        );
    }


    if (
        inspection.signals.some(
            signal =>
                signal
                    .toLowerCase()
                    .includes("encoded characters")
        )
    ) {

        score += 5;

        reasons.push(
            "URL contains encoded characters."
        );
    }


    if (
        inspection.signals.some(
            signal =>
                signal
                    .toLowerCase()
                    .includes("unusually long")
        )
    ) {

        score += 5;

        reasons.push(
            "URL is unusually long."
        );
    }


    if (
        inspection.liveCheck.redirects.length >= 2
    ) {

        score += 10;

        reasons.push(
            "URL uses multiple redirects."
        );
    }


    // ==================================================
    // PRIVATE IP
    // ==================================================

    if (
        inspection.signals.some(
            signal =>
                signal
                    .toLowerCase()
                    .includes("private/internal")
        )
    ) {

        score += 30;

        reasons.push(
            "URL resolves to a private or internal IP address."
        );
    }


    // ==================================================
    // VIRUSTOTAL
    // ==================================================

    if (
        virusTotal.available &&
        virusTotal.found
    ) {

        const malicious =
            virusTotal.analysisStats?.malicious || 0;


        const suspicious =
            virusTotal.analysisStats?.suspicious || 0;


        if (malicious >= 5) {

            score += 50;

            reasons.push(
                `VirusTotal reports ${malicious} malicious detections.`
            );

        } else if (malicious >= 2) {

            score += 35;

            reasons.push(
                `VirusTotal reports ${malicious} malicious detections.`
            );

        } else if (malicious === 1) {

            score += 20;

            reasons.push(
                "VirusTotal reports 1 malicious detection."
            );
        }


        if (suspicious >= 5) {

            score += 20;

            reasons.push(
                `VirusTotal reports ${suspicious} suspicious detections.`
            );

        } else if (suspicious >= 2) {

            score += 10;

            reasons.push(
                `VirusTotal reports ${suspicious} suspicious detections.`
            );

        } else if (suspicious === 1) {

            score += 5;

            reasons.push(
                "VirusTotal reports 1 suspicious detection."
            );
        }
    }


    score =
        Math.max(
            0,
            Math.min(
                100,
                score
            )
        );


    return {

        score,

        level:
            getRiskLevel(score),

        reasons

    };
}


// ==================================================
// GEMINI URL ANALYSIS
// ==================================================

async function analyzeURLWithGemini(
    inspection,
    virusTotal,
    riskEngine
) {

    if (!process.env.GEMINI_API_KEY) {

        throw new Error(
            "GEMINI_API_KEY is not configured in .env"
        );
    }


    const prompt = `

You are ScamGuard AI, a cybersecurity URL risk analyst.

Analyze ONLY the evidence supplied below.

Return ONLY valid JSON:

{
  "risk": 0,
  "explanation": "short explanation"
}

Risk levels:

0-29 = LOW RISK
30-69 = SUSPICIOUS
70-100 = HIGH RISK

ScamGuard technical base risk:
${riskEngine.score}/100

Base level:
${riskEngine.level}

Base reasons:
${riskEngine.reasons.join("\n") || "None"}

VirusTotal available:
${virusTotal.available}

VirusTotal found:
${virusTotal.found ?? "Unknown"}

Malicious detections:
${virusTotal.analysisStats?.malicious ?? "Unknown"}

Suspicious detections:
${virusTotal.analysisStats?.suspicious ?? "Unknown"}

Harmless detections:
${virusTotal.analysisStats?.harmless ?? "Unknown"}

Undetected:
${virusTotal.analysisStats?.undetected ?? "Unknown"}

VirusTotal reputation:
${virusTotal.reputation ?? "Unknown"}

Technical evidence:

Original URL:
${inspection.originalURL}

Hostname:
${inspection.hostname}

Protocol:
${inspection.protocol}

Resolved IPs:
${inspection.resolvedIPs.join(", ") || "None"}

Signals:
${inspection.signals.join("\n") || "None"}

Live server reachable:
${inspection.liveCheck.reachable}

HTTP status:
${inspection.liveCheck.status ?? "Unknown"}

HTTP status text:
${inspection.liveCheck.statusText ?? "Unknown"}

Final URL:
${inspection.liveCheck.finalURL}

Redirects:
${inspection.liveCheck.redirects.join("\n") || "None"}

Rules:

- Use the deterministic base risk as strong evidence.
- Do not call a URL safe simply because VirusTotal has no record.
- Do not call a URL malicious because of only one suspicious word.
- Multiple malicious VirusTotal detections are strong evidence.
- HTTPS alone does not prove safety.
- A failed DNS lookup does not prove maliciousness.
- Do not invent information.
- Keep explanation short.
- Return ONLY JSON.
`;


    // Real request timeout.
    // The previous AbortController was created but
    // was never attached to the Gemini request.

    const geminiPromise =
        gemini.models.generateContent({

            model:
                process.env.GEMINI_MODEL ||
                "gemini-2.5-flash",

            contents:
                prompt,

            config: {

                temperature: 0.2,

                responseMimeType:
                    "application/json"

            }

        });


    const response =
        await withTimeout(
            geminiPromise,
            4000,
            "Gemini URL analysis timed out."
        );


    const result =
        response.text;


    const data =
        safeJSONParse(result);


    if (
        typeof data.risk !== "number" ||
        typeof data.explanation !== "string"
    ) {

        throw new Error(
            "Gemini returned an invalid response format."
        );
    }


    return {

        risk:
            clampRisk(data.risk),

        explanation:
            data.explanation.trim()

    };
}


// ==================================================
// MESSAGE SCANNER
// ==================================================

app.post(
    "/check-message",
    async (req, res) => {

        try {

            const message =
                String(
                    req.body?.message || ""
                ).trim();


            if (!message) {

                return res.status(400).json({

                    error:
                        "Message is required."

                });
            }


            if (message.length > 10000) {

                return res.status(400).json({

                    error:
                        "Message is too long."

                });
            }


            const completion =
                await client.chat.completions.create({

                    model:
                        "deepseek-chat",

                    messages: [

                        {

                            role:
                                "system",

                            content: `

You are ScamGuard AI, a cybersecurity scam-message detector.

Return ONLY valid JSON:

{
  "risk": 0,
  "explanation": "short explanation"
}

Risk:
0-29 = LOW RISK
30-69 = SUSPICIOUS
70-100 = HIGH RISK

Look for:
- urgency
- OTP/password requests
- suspicious links
- money requests
- fake prizes
- account threats
- impersonation
- phishing
- unusual payment requests

Do not assume every link is malicious.

`

                        },

                        {

                            role:
                                "user",

                            content:
                                message

                        }

                    ]

                });


            const result =
                completion
                    .choices?.[0]
                    ?.message?.content;


            const data =
                safeJSONParse(result);


            if (
                typeof data.risk !== "number" ||
                typeof data.explanation !== "string"
            ) {

                throw new Error(
                    "Invalid response returned by DeepSeek."
                );
            }


            const risk =
                clampRisk(data.risk);


            res.json({

                risk,

                riskLevel:
                    getRiskLevel(risk),

                explanation:
                    data.explanation.trim(),

                aiEngine:
                    "DeepSeek"

            });

        } catch (error) {

            console.error(
                "❌ DeepSeek Message Error:",
                error.message
            );


            res.status(500).json({

                error:
                    "DeepSeek message analysis failed."

            });
        }
    }
);


// ==================================================
// EMAIL SCANNER
// ==================================================

app.post(
    "/check-email",
    async (req, res) => {

        try {

            const sender =
                String(
                    req.body?.sender || ""
                ).trim();


            const subject =
                String(
                    req.body?.subject || ""
                ).trim();


            const body =
                String(
                    req.body?.body || ""
                ).trim();


            const link =
                String(
                    req.body?.link || ""
                ).trim();


            if (!sender || !subject || !body) {

                return res.status(400).json({

                    error:
                        "Sender, subject and email body are required."

                });
            }


            if (
                sender.length > 500 ||
                subject.length > 1000 ||
                body.length > 20000 ||
                link.length > 5000
            ) {

                return res.status(400).json({

                    error:
                        "One or more email fields are too long."

                });
            }


            const completion =
                await client.chat.completions.create({

                    model:
                        "deepseek-chat",

                    messages: [

                        {

                            role:
                                "system",

                            content: `

You are ScamGuard AI, a cybersecurity email scam detector.

Return ONLY valid JSON:

{
  "risk": 0,
  "explanation": "short explanation"
}

Risk:
0-29 = LOW RISK
30-69 = SUSPICIOUS
70-100 = HIGH RISK

Analyze:
- sender email
- subject
- body
- provided link

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
- suspicious domains

Do not assume an email is malicious merely because it contains a link.

`

                        },

                        {

                            role:
                                "user",

                            content: `

Sender:
${sender}

Subject:
${subject}

Body:
${body}

Link:
${link || "No link provided"}

`

                        }

                    ]

                });


            const result =
                completion
                    .choices?.[0]
                    ?.message?.content;


            const data =
                safeJSONParse(result);


            if (
                typeof data.risk !== "number" ||
                typeof data.explanation !== "string"
            ) {

                throw new Error(
                    "Invalid response returned by DeepSeek."
                );
            }


            const risk =
                clampRisk(data.risk);


            res.json({

                risk,

                riskLevel:
                    getRiskLevel(risk),

                explanation:
                    data.explanation.trim(),

                aiEngine:
                    "DeepSeek"

            });

        } catch (error) {

            console.error(
                "❌ DeepSeek Email Error:",
                error.message
            );


            res.status(500).json({

                error:
                    "DeepSeek email analysis failed."

            });
        }
    }
);


// ==================================================
// URL SCANNER
// ==================================================

app.post(
    "/check-url",
    async (req, res) => {

        const scanStart =
            Date.now();


        try {

            const rawURL =
                String(
                    req.body?.url || ""
                ).trim();


            if (!rawURL) {

                return res.status(400).json({

                    error:
                        "URL is required."

                });
            }


            let url;


            try {

                url =
                    normalizeURL(rawURL);

            } catch {

                return res.status(400).json({

                    error:
                        "Please provide a valid HTTP or HTTPS URL."

                });
            }


            console.log("");
            console.log(
                "🔗 URL received:",
                url
            );


            // ==================================================
            // RUN INSPECTION + VIRUSTOTAL IN PARALLEL
            // ==================================================

            console.log(
                "⚡ Starting parallel URL checks..."
            );


            const [
                inspection,
                virusTotal
            ] =
                await Promise.all([

                    inspectURL(url),

                    checkVirusTotalURL(url)

                ]);


            console.log(
                "🔎 URL Inspection completed."
            );


            console.log(
                "🛡️ VirusTotal check completed."
            );


            // ==================================================
            // RISK ENGINE
            // ==================================================

            const riskEngine =
                calculateURLRisk(
                    inspection,
                    virusTotal
                );


            console.log(
                "⚙️ ScamGuard Risk:",
                riskEngine
            );


            // ==================================================
            // GEMINI
            // ==================================================

            let geminiResult;


            try {

                geminiResult =
                    await analyzeURLWithGemini(
                        inspection,
                        virusTotal,
                        riskEngine
                    );


                console.log(
                    "🤖 Gemini URL analysis completed."
                );

            } catch (error) {

                console.error(
                    "⚠️ Gemini URL Analysis Error:",
                    error.message
                );


                // Use deterministic risk if Gemini
                // is slow or unavailable.

                geminiResult = {

                    risk:
                        riskEngine.score,

                    explanation:
                        riskEngine.reasons.length > 0
                            ? riskEngine.reasons.join(" ")
                            : "No major technical risk indicators were detected."

                };
            }


            const finalRisk =
                clampRisk(
                    geminiResult.risk
                );


            const finalLevel =
                getRiskLevel(
                    finalRisk
                );


            const totalTime =
                Date.now() -
                scanStart;


            console.log(
                `✅ URL scan completed in ${totalTime} ms`
            );


            // ==================================================
            // RESPONSE
            // ==================================================

            res.json({

                risk:
                    finalRisk,

                riskLevel:
                    finalLevel,

                baseRisk:
                    riskEngine.score,

                explanation:
                    geminiResult.explanation,

                scanTime:
                    totalTime,

                details: {

                    hostname:
                        inspection.hostname,

                    protocol:
                        inspection.protocol,

                    port:
                        inspection.port,

                    resolvedIPs:
                        inspection.resolvedIPs,

                    liveCheck:
                        inspection.liveCheck,

                    signals:
                        inspection.signals,

                    riskEngine: {

                        score:
                            riskEngine.score,

                        level:
                            riskEngine.level,

                        reasons:
                            riskEngine.reasons

                    },

                    virusTotal:
                        virusTotal,

                    aiEngine:
                        "Gemini"

                }

            });

        } catch (error) {

            console.error(
                "❌ URL Analysis Error:",
                error
            );


            res.status(500).json({

                error:
                    "Dynamic URL analysis failed.",

                details:
                    error.message

            });
        }
    }
);


// ==================================================
// HEALTH CHECK
// ==================================================

app.get(
    "/health",
    (req, res) => {

        res.json({

            status:
                "ok",

            scamGuard:
                "online",

            gemini:
                Boolean(
                    process.env.GEMINI_API_KEY
                ),

            deepseek:
                Boolean(
                    process.env.DEEPSEEK_API_KEY
                ),

            virusTotal:
                Boolean(
                    process.env.VIRUSTOTAL_API_KEY
                )

        });
    }
);


// ==================================================
// START SERVER
// ==================================================

app.listen(
    PORT,
    () => {

        console.log("");

        console.log(
            "=============================================="
        );

        console.log(
            "🛡️  ScamGuard AI"
        );

        console.log(
            `🌐 http://localhost:${PORT}`
        );

        console.log(
            `❤️  Health: http://localhost:${PORT}/health`
        );

        console.log(
            `🤖 Gemini: ${
                process.env.GEMINI_API_KEY
                    ? "Configured"
                    : "NOT CONFIGURED"
            }`
        );

        console.log(
            `🧠 DeepSeek: ${
                process.env.DEEPSEEK_API_KEY
                    ? "Configured"
                    : "NOT CONFIGURED"
            }`
        );

        console.log(
            `🛡️  VirusTotal: ${
                process.env.VIRUSTOTAL_API_KEY
                    ? "Configured"
                    : "Optional / Not configured"
            }`
        );

        console.log(
            "=============================================="
        );

        console.log("");
    }
);