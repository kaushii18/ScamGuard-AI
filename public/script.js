// ==================================================
// SOAP BUBBLE CLICK EFFECT
// ==================================================

document.addEventListener("click", function (e) {

    // Don't create bubbles when clicking form controls/buttons
    if (
        e.target.tagName === "BUTTON" ||
        e.target.tagName === "INPUT" ||
        e.target.tagName === "TEXTAREA"
    ) {
        return;
    }

    const bubble = document.createElement("div");

    bubble.classList.add("soap-bubble");

    // Random size: 30px - 70px
    const size = Math.floor(Math.random() * 40) + 30;

    bubble.style.width = `${size}px`;
    bubble.style.height = `${size}px`;

    // Exact click position
    bubble.style.left = `${e.clientX - size / 2}px`;
    bubble.style.top = `${e.clientY - size / 2}px`;

    document.body.appendChild(bubble);

    // Remove after animation
    setTimeout(() => {
        bubble.remove();
    }, 1800);
});


// ==================================================
// ELEMENTS
// ==================================================

const messageBox = document.querySelector("#messageBox");

const senderEmail = document.querySelector("#senderEmail");
const emailSubject = document.querySelector("#emailSubject");
const emailBody = document.querySelector("#emailBody");
const emailLink = document.querySelector("#emailLink");

const messageScanner = document.querySelector("#messageScanner");
const emailScanner = document.querySelector("#emailScanner");

const checkButton = document.querySelector("#checkButton");
const clearButton = document.querySelector("#clearButton");

const resultBox = document.querySelector(".result");
const riskLevel = document.querySelector(".risk-level");
const analysis = document.querySelector(".analysis");

const messageOption = document.querySelector("#messageOption");
const emailOption = document.querySelector("#emailOption");


// ==================================================
// DEFAULT: MESSAGE
// ==================================================

messageOption.classList.add("active");
emailOption.classList.remove("active");

messageScanner.style.display = "block";
emailScanner.style.display = "none";

checkButton.textContent = "🔍 Check Message";


// ==================================================
// MESSAGE OPTION
// ==================================================

messageOption.addEventListener("click", function () {

    console.log("💬 Message button clicked");

    messageOption.classList.add("active");
    emailOption.classList.remove("active");

    messageScanner.style.display = "block";
    emailScanner.style.display = "none";

    checkButton.textContent = "🔍 Check Message";

    resultBox.style.display = "none";

});


// ==================================================
// EMAIL OPTION
// ==================================================

emailOption.addEventListener("click", function () {

    console.log("📧 Email button clicked");

    emailOption.classList.add("active");
    messageOption.classList.remove("active");

    messageScanner.style.display = "none";
    emailScanner.style.display = "block";

    checkButton.textContent = "📧 Check Email";

    resultBox.style.display = "none";

});


// ==================================================
// CHECK BUTTON
// ==================================================

checkButton.addEventListener("click", async function () {

    // ==================================================
    // EMAIL SCANNER
    // ==================================================

    if (emailOption.classList.contains("active")) {

        const sender = senderEmail.value.trim();
        const subject = emailSubject.value.trim();
        const body = emailBody.value.trim();
        const link = emailLink.value.trim();

        // Validate
        if (!sender || !subject || !body) {

            alert(
                "Please enter sender email, subject and email content."
            );

            return;
        }

        // Loading
        checkButton.disabled = true;
        checkButton.textContent = "📧 Checking Email...";

        resultBox.style.display = "block";

        analysis.textContent =
            "AI is analyzing the email...";

        try {

            const response = await fetch("/check-email", {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    sender: sender,
                    subject: subject,
                    body: body,
                    link: link
                })

            });

            const data = await response.json();

            if (!response.ok) {

                throw new Error(
                    data.error || "Email analysis failed."
                );

            }

            const risk = Number(data.risk);

            // Safety check
            if (Number.isNaN(risk)) {

                throw new Error(
                    "Invalid risk value returned by server."
                );

            }

            riskLevel.style.width =
                `${Math.max(0, Math.min(100, risk))}%`;


            // Risk message
            if (risk >= 70) {

                resultBox.querySelector("h2").textContent =
                    `🚨 High Scam Risk: ${risk}%`;

            }

            else if (risk >= 30) {

                resultBox.querySelector("h2").textContent =
                    `⚠️ Possible Scam: ${risk}%`;

            }

            else {

                resultBox.querySelector("h2").textContent =
                    `✅ Low Scam Risk: ${risk}%`;

            }


            // AI explanation
            analysis.textContent =
                data.explanation || "No explanation received.";

        }

        catch (error) {

            console.error(
                "❌ Email Analysis Error:",
                error
            );

            resultBox.querySelector("h2").textContent =
                "❌ Email Analysis Error";

            analysis.textContent =
                "Unable to analyze the email. Please check your server and API key.";

        }

        finally {

            checkButton.disabled = false;
            checkButton.textContent = "📧 Check Email";

        }

        return;
    }


    // ==================================================
    // MESSAGE SCANNER
    // ==================================================

    const message =
        messageBox.value.trim();

    // Validate
    if (!message) {

        alert(
            "Please paste a message first."
        );

        return;
    }


    // Loading
    checkButton.disabled = true;

    checkButton.textContent =
        "🔍 Checking...";

    resultBox.style.display =
        "block";

    analysis.textContent =
        "AI is analyzing the message...";


    try {

        const response = await fetch(
            "/check-message",
            {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    message: message
                })

            }
        );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Message analysis failed."
            );

        }


        const risk =
            Number(data.risk);


        // Safety check
        if (Number.isNaN(risk)) {

            throw new Error(
                "Invalid risk value returned by server."
            );

        }


        // Risk bar
        riskLevel.style.width =
            `${Math.max(0, Math.min(100, risk))}%`;


        // Risk message
        if (risk >= 70) {

            resultBox.querySelector("h2").textContent =
                `🚨 High Scam Risk: ${risk}%`;

        }

        else if (risk >= 30) {

            resultBox.querySelector("h2").textContent =
                `⚠️ Possible Scam: ${risk}%`;

        }

        else {

            resultBox.querySelector("h2").textContent =
                `✅ Low Scam Risk: ${risk}%`;

        }


        // AI explanation
        analysis.textContent =
            data.explanation || "No explanation received.";

    }


    catch (error) {

        console.error(
            "❌ Message Analysis Error:",
            error
        );

        resultBox.querySelector("h2").textContent =
            "❌ Message Analysis Error";

        analysis.textContent =
            "Unable to analyze the message. Please check your server and API key.";

    }


    finally {

        checkButton.disabled = false;

        checkButton.textContent =
            "🔍 Check Message";

    }

});


// ==================================================
// CLEAR BUTTON
// ==================================================

clearButton.addEventListener("click", function () {

    // Clear message
    messageBox.value = "";


    // Clear email
    senderEmail.value = "";
    emailSubject.value = "";
    emailBody.value = "";
    emailLink.value = "";


    // Hide result
    resultBox.style.display =
        "none";


    // Reset risk bar
    riskLevel.style.width =
        "0%";


    // Clear explanation
    analysis.textContent =
        "";


    // Reset result title
    resultBox.querySelector("h2").textContent =
        "⚠️ Risk Analysis";

});