require("dotenv").config();

const express = require("express");
const OpenAI = require("openai");

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.static("public"));

// DeepSeek client
const client = new OpenAI({
    apiKey: process.env.DEEPSEEK_API_KEY,
    baseURL: "https://api.deepseek.com"
});

// ScamGuard AI API
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

        // Remove Markdown code fences if DeepSeek adds them
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

// Start server
app.listen(PORT, () => {
    console.log(
        `🛡️ ScamGuard AI server is running at http://localhost:${PORT}`
    );
});