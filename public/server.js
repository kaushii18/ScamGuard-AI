const express = require("express");
const OpenAI = require("openai");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static("public"));

const client = new OpenAI({
    apiKey: process.env.DEEPSEEK_API_KEY,
    baseURL: "https://api.deepseek.com"
});

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
- Look for urgency, requests for OTP/passwords,
  suspicious links, money requests, fake prizes,
  account threats, impersonation and other scam signals.
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

        res.json(data);

    } catch (error) {

        console.error("DeepSeek Error:", error);

        res.status(500).json({
            error: "DeepSeek API request failed."
        });
    }
});

app.listen(PORT, () => {

    console.log(
        `ScamGuard AI server is running at http://localhost:${PORT}`
    );

});