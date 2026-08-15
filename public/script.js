const messageBox = document.querySelector("textarea");
const checkButton = document.querySelector("button");
const resultBox = document.querySelector(".result");
const riskLevel = document.querySelector(".risk-level");
const analysis = document.querySelector(".analysis");

checkButton.addEventListener("click", async function () {

    const message = messageBox.value.trim();

    if (message === "") {
        alert("Please paste a message first.");
        return;
    }

    checkButton.disabled = true;
    checkButton.textContent = "🔍 Checking...";

    resultBox.style.display = "block";
    analysis.textContent = "AI is analyzing the message...";

    try {

        const response = await fetch("/check-message", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                message: message
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Something went wrong.");
        }

        const risk = data.risk;

        riskLevel.style.width = risk + "%";

        if (risk >= 70) {

            resultBox.querySelector("h2").textContent =
                "🚨 High Scam Risk: " + risk + "%";

        } else if (risk >= 30) {

            resultBox.querySelector("h2").textContent =
                "⚠️ Possible Scam: " + risk + "%";

        } else {

            resultBox.querySelector("h2").textContent =
                "✅ Low Scam Risk: " + risk + "%";
        }

        analysis.textContent = data.explanation;

    } catch (error) {

        console.error(error);

        resultBox.querySelector("h2").textContent =
            "❌ Error";

        analysis.textContent =
            "Unable to analyze the message. Please check your server and API key.";

    }

    checkButton.disabled = false;
    checkButton.textContent = "🔍 Check Message";
});