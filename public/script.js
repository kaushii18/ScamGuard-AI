// =========================
// ELEMENTS
// =========================

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


// =========================
// DEFAULT: MESSAGE
// =========================

messageOption.classList.add("active");
emailOption.classList.remove("active");

messageScanner.style.display = "block";
emailScanner.style.display = "none";

checkButton.textContent = "🔍 Check Message";


// =========================
// MESSAGE OPTION
// =========================

messageOption.addEventListener("click", function () {

    console.log("💬 Message button clicked");

    messageOption.classList.add("active");
    emailOption.classList.remove("active");

    messageScanner.style.display = "block";
    emailScanner.style.display = "none";

    checkButton.textContent = "🔍 Check Message";

    resultBox.style.display = "none";

});


// =========================
// EMAIL OPTION
// =========================

emailOption.addEventListener("click", function () {

    console.log("📧 Email button clicked");

    emailOption.classList.add("active");
    messageOption.classList.remove("active");

    messageScanner.style.display = "none";
    emailScanner.style.display = "block";

    checkButton.textContent = "📧 Check Email";

    resultBox.style.display = "none";

});


// =========================
// CHECK BUTTON
// =========================

checkButton.addEventListener("click", async function () {


    // ==================================================
    // EMAIL SCANNER
    // ==================================================

    if (emailOption.classList.contains("active")) {

        const sender = senderEmail.value.trim();
        const subject = emailSubject.value.trim();
        const body = emailBody.value.trim();
        const link = emailLink.value.trim();


        // -------------------------
        // VALIDATE EMAIL INPUT
        // -------------------------

        if (!sender || !subject || !body) {

            alert(
                "Please enter sender email, subject and email content."
            );

            return;
        }


        // -------------------------
        // LOADING
        // -------------------------

        checkButton.disabled = true;

        checkButton.textContent =
            "📧 Checking Email...";

        resultBox.style.display = "block";

        analysis.textContent =
            "AI is analyzing the email...";


        try {

            // -------------------------
            // SEND EMAIL TO SERVER
            // -------------------------

            const response = await fetch(
                "/check-email",
                {

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

                }
            );


            // -------------------------
            // GET SERVER RESPONSE
            // -------------------------

            const data =
                await response.json();


            // -------------------------
            // CHECK SERVER ERROR
            // -------------------------

            if (!response.ok) {

                throw new Error(
                    data.error ||
                    "Email analysis failed."
                );

            }


            // -------------------------
            // GET RISK
            // -------------------------

            const risk =
                Number(data.risk);


            // -------------------------
            // UPDATE RISK BAR
            // -------------------------

            riskLevel.style.width =
                risk + "%";


            // -------------------------
            // RISK MESSAGE
            // -------------------------

            if (risk >= 70) {

                resultBox.querySelector("h2").textContent =
                    "🚨 High Scam Risk: " +
                    risk +
                    "%";

            }

            else if (risk >= 30) {

                resultBox.querySelector("h2").textContent =
                    "⚠️ Possible Scam: " +
                    risk +
                    "%";

            }

            else {

                resultBox.querySelector("h2").textContent =
                    "✅ Low Scam Risk: " +
                    risk +
                    "%";

            }


            // -------------------------
            // AI EXPLANATION
            // -------------------------

            analysis.textContent =
                data.explanation;


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


        // -------------------------
        // RESET BUTTON
        // -------------------------

        checkButton.disabled = false;

        checkButton.textContent =
            "📧 Check Email";


        return;
    }


    // ==================================================
    // MESSAGE SCANNER
    // ==================================================

    const message =
        messageBox.value.trim();


    // -------------------------
    // VALIDATE MESSAGE
    // -------------------------

    if (!message) {

        alert(
            "Please paste a message first."
        );

        return;
    }


    // -------------------------
    // LOADING
    // -------------------------

    checkButton.disabled = true;

    checkButton.textContent =
        "🔍 Checking...";

    resultBox.style.display =
        "block";

    analysis.textContent =
        "AI is analyzing the message...";


    try {

        // -------------------------
        // SEND MESSAGE TO SERVER
        // -------------------------

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


        // -------------------------
        // GET RESPONSE
        // -------------------------

        const data =
            await response.json();


        // -------------------------
        // CHECK ERROR
        // -------------------------

        if (!response.ok) {

            throw new Error(
                data.error ||
                "Message analysis failed."
            );

        }


        // -------------------------
        // GET RISK
        // -------------------------

        const risk =
            Number(data.risk);


        // -------------------------
        // UPDATE RISK BAR
        // -------------------------

        riskLevel.style.width =
            risk + "%";


        // -------------------------
        // RISK MESSAGE
        // -------------------------

        if (risk >= 70) {

            resultBox.querySelector("h2").textContent =
                "🚨 High Scam Risk: " +
                risk +
                "%";

        }

        else if (risk >= 30) {

            resultBox.querySelector("h2").textContent =
                "⚠️ Possible Scam: " +
                risk +
                "%";

        }

        else {

            resultBox.querySelector("h2").textContent =
                "✅ Low Scam Risk: " +
                risk +
                "%";

        }


        // -------------------------
        // AI EXPLANATION
        // -------------------------

        analysis.textContent =
            data.explanation;


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


    // -------------------------
    // RESET BUTTON
    // -------------------------

    checkButton.disabled = false;

    checkButton.textContent =
        "🔍 Check Message";

});


// ==================================================
// CLEAR BUTTON
// ==================================================

clearButton.addEventListener("click", function () {

    // -------------------------
    // CLEAR MESSAGE
    // -------------------------

    messageBox.value = "";


    // -------------------------
    // CLEAR EMAIL
    // -------------------------

    senderEmail.value = "";

    emailSubject.value = "";

    emailBody.value = "";

    emailLink.value = "";


    // -------------------------
    // HIDE RESULT
    // -------------------------

    resultBox.style.display =
        "none";


    // -------------------------
    // RESET RISK BAR
    // -------------------------

    riskLevel.style.width =
        "0%";


    // -------------------------
    // CLEAR EXPLANATION
    // -------------------------

    analysis.textContent =
        "";


    // -------------------------
    // RESET RESULT TITLE
    // -------------------------

    resultBox.querySelector("h2").textContent =
        "⚠️ Risk Analysis";

});