const messageBox = document.querySelector("#messageBox");
const emailBody = document.querySelector("#emailBody");

const senderEmail = document.querySelector("#senderEmail");
const emailSubject = document.querySelector("#emailSubject");
const emailLink = document.querySelector("#emailLink");

const messageScanner = document.querySelector("#messageScanner");
const emailScanner = document.querySelector("#emailScanner");

const checkButton = document.querySelector("#checkButton");
const clearButton = document.querySelector("#clearButton");

const resultBox = document.querySelector(".result");
const riskLevel = document.querySelector(".risk-level");
const analysis = document.querySelector(".analysis");


// Message / Email options
const messageOption = document.querySelector("#messageOption");
const emailOption = document.querySelector("#emailOption");


// Message is selected by default
messageOption.classList.add("active");
emailScanner.style.display = "none";
messageScanner.style.display = "block";


/* =========================
   CHECK BUTTON
========================= */

checkButton.addEventListener("click", async function () {

    // For now, only Message scanner uses AI
    // Email AI verification will be added in Step 5B+

    if (emailOption.classList.contains("active")) {

        alert("📧 Email scanner UI is ready! Email verification will be connected next.");

        return;
    }


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


        /* =========================
           RISK LEVEL
        ========================= */

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


        /* =========================
           AI EXPLANATION
        ========================= */

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


/* =========================
   CLEAR BUTTON
========================= */

clearButton.addEventListener("click", function () {

    // Clear Message
    messageBox.value = "";

    // Clear Email fields
    senderEmail.value = "";
    emailSubject.value = "";
    emailBody.value = "";
    emailLink.value = "";

    // Hide result
    resultBox.style.display = "none";

    // Reset risk bar
    riskLevel.style.width = "0%";

    // Clear explanation
    analysis.textContent = "";

});


/* =========================
   MESSAGE OPTION
========================= */

messageOption.addEventListener("click", function () {

    // Select Message
    messageOption.classList.add("active");

    // Remove Email selection
    emailOption.classList.remove("active");


    // Show Message scanner
    messageScanner.style.display = "block";

    // Hide Email scanner
    emailScanner.style.display = "none";


    // Change button
    checkButton.textContent = "🔍 Check Message";


    // Reset placeholder
    messageBox.placeholder =
        "Paste a suspicious message here…";

});


/* =========================
   EMAIL OPTION
========================= */

emailOption.addEventListener("click", function () {

    // Select Email
    emailOption.classList.add("active");

    // Remove Message selection
    messageOption.classList.remove("active");


    // Hide Message scanner
    messageScanner.style.display = "none";

    // Show Email scanner
    emailScanner.style.display = "block";


    // Change button
    checkButton.textContent = "📧 Check Email";

});