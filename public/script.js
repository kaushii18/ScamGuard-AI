 const messageBox = document.querySelector("textarea");
const checkButton = document.querySelector("button");
const resultBox = document.querySelector(".result");
const riskLevel = document.querySelector(".risk-level");

checkButton.addEventListener("click", function () {

    const message = messageBox.value.trim();

    if (message === "") {
        alert("Please paste a message first.");
        return;
    }

    let risk = 0;

    const scamWords = [
        "urgent",
        "otp",
        "password",
        "click here",
        "verify",
        "bank",
        "winner",
        "prize",
        "account blocked",
        "send money"
    ];

    scamWords.forEach(function (word) {
        if (message.toLowerCase().includes(word)) {
            risk += 10;
        }
    });

    if (risk > 100) {
        risk = 100;
    }

    resultBox.style.display = "block";
    riskLevel.style.width = risk + "%";

    if (risk >= 50) {
        resultBox.querySelector("h2").textContent =
            "🚨 High Scam Risk: " + risk + "%";
    } else if (risk > 0) {
        resultBox.querySelector("h2").textContent =
            "⚠️ Possible Scam: " + risk + "%";
    } else {
        resultBox.querySelector("h2").textContent =
            "✅ Low Scam Risk: " + risk + "%";
    }
});