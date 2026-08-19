const express = require("express");
const OpenAI = require("openai");

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


// =========================
// MESSAGE SCANNER
// =========================

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


    } catch (error) {

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


// =========================
// EMAIL SCANNER
// STEP 5C + 5D
// =========================

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


        // =========================
        // GET DEEPSEEK RESPONSE
        // =========================

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


        // =========================
        // CLEAN RESPONSE
        // =========================

        const cleanedResult =
            result
                .replace(/```json/gi, "")
                .replace(/```/g, "")
                .trim();


        // =========================
        // PARSE JSON
        // =========================

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
                Math.min(100, data.risk)
            );


        // =========================
        // SEND RESULT TO FRONTEND
        // =========================

        res.json({

            risk: risk,

            explanation:
                data.explanation

        });


    } catch (error) {

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


// =========================
// START SERVER
// =========================

app.listen(PORT, () => {

    console.log(
        `🛡️ ScamGuard AI server is running at http://localhost:${PORT}`
    );

});