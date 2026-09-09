// ==================================================
// SCAMGUARD AI - SCRIPT.JS
// ==================================================


// ==================================================
// SOAP BUBBLE CLICK EFFECT
// ==================================================

document.addEventListener("click", function (e) {

    if (
        e.target.tagName === "BUTTON" ||
        e.target.tagName === "INPUT" ||
        e.target.tagName === "TEXTAREA"
    ) {
        return;
    }

    const bubble = document.createElement("div");
    bubble.classList.add("soap-bubble");

    const size = Math.floor(Math.random() * 40) + 30;

    bubble.style.width = `${size}px`;
    bubble.style.height = `${size}px`;
    bubble.style.left = `${e.clientX - size / 2}px`;
    bubble.style.top = `${e.clientY - size / 2}px`;

    document.body.appendChild(bubble);

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

const urlInput = document.querySelector("#urlInput");

const messageScanner = document.querySelector("#messageScanner");
const emailScanner = document.querySelector("#emailScanner");
const urlScanner = document.querySelector("#urlScanner");

const checkButton = document.querySelector("#checkButton");
const clearButton = document.querySelector("#clearButton");

const resultBox = document.querySelector(".result");

const messageOption = document.querySelector("#messageOption");
const emailOption = document.querySelector("#emailOption");
const urlOption = document.querySelector("#urlOption");


// ==================================================
// CHECK REQUIRED ELEMENTS
// ==================================================

if (
    !messageBox ||
    !senderEmail ||
    !emailSubject ||
    !emailBody ||
    !emailLink ||
    !urlInput ||
    !messageScanner ||
    !emailScanner ||
    !urlScanner ||
    !checkButton ||
    !clearButton ||
    !resultBox ||
    !messageOption ||
    !emailOption ||
    !urlOption
) {

    console.error(
        "❌ ScamGuard AI: One or more HTML elements are missing."
    );

}


// ==================================================
// HELPER - ESCAPE HTML
// ==================================================

function escapeHTML(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}


// ==================================================
// HELPER - SHOW RESULT
// ==================================================

function showResultBox() {

    resultBox.style.display = "block";

}


// ==================================================
// HELPER - RISK TEXT
// ==================================================

function getRiskText(risk) {

    if (risk >= 70) {

        return `🚨 High Scam Risk: ${Math.round(risk)}%`;

    }

    if (risk >= 30) {

        return `⚠️ Possible Scam: ${Math.round(risk)}%`;

    }

    return `✅ Low Scam Risk: ${Math.round(risk)}%`;

}


// ==================================================
// HELPER - DISPLAY BASIC RESULT
// ==================================================

function displayBasicResult(risk, explanation) {

    const safeRisk = Math.max(
        0,
        Math.min(100, Number(risk))
    );

    resultBox.innerHTML = `

        <h2>
            ${getRiskText(safeRisk)}
        </h2>

        <div class="risk-score-display">

            <span class="risk-number">
                ${Math.round(safeRisk)}
            </span>

            <span class="risk-out-of">
                / 100
            </span>

        </div>

        <div class="risk-bar">

            <div
                class="risk-level"
                style="width: ${safeRisk}%"
            ></div>

        </div>

        <div class="analysis">
            ${escapeHTML(
                explanation || "No explanation received."
            )}
        </div>

    `;

}


// ==================================================
// DEFAULT MESSAGE MODE
// ==================================================

function setMessageMode() {

    messageOption.classList.add("active");
    emailOption.classList.remove("active");
    urlOption.classList.remove("active");

    messageScanner.style.display = "block";
    emailScanner.style.display = "none";
    urlScanner.style.display = "none";

    checkButton.textContent = "🔍 Check Message";

    resultBox.style.display = "none";

}


// ==================================================
// EMAIL MODE
// ==================================================

function setEmailMode() {

    messageOption.classList.remove("active");
    emailOption.classList.add("active");
    urlOption.classList.remove("active");

    messageScanner.style.display = "none";
    emailScanner.style.display = "block";
    urlScanner.style.display = "none";

    checkButton.textContent = "📧 Check Email";

    resultBox.style.display = "none";

}


// ==================================================
// URL MODE
// ==================================================

function setURLMode() {

    messageOption.classList.remove("active");
    emailOption.classList.remove("active");
    urlOption.classList.add("active");

    messageScanner.style.display = "none";
    emailScanner.style.display = "none";
    urlScanner.style.display = "block";

    checkButton.textContent = "🔗 Check URL";

    resultBox.style.display = "none";

}


// ==================================================
// OPTION BUTTONS
// ==================================================

messageOption.addEventListener(
    "click",
    setMessageMode
);

emailOption.addEventListener(
    "click",
    setEmailMode
);

urlOption.addEventListener(
    "click",
    setURLMode
);


// ==================================================
// URL SECURITY DETAILS
// ==================================================

function displayURLSecurityDetails(data) {

    const details = data.details || {};

    const liveCheck =
        details.liveCheck || {};

    const signals =
        Array.isArray(details.signals)
            ? details.signals
            : [];

    const resolvedIPs =
        Array.isArray(details.resolvedIPs)
            ? details.resolvedIPs
            : [];

    const virusTotal =
        details.virusTotal || null;


    // Remove previous details

    const oldDetails =
        resultBox.querySelector(
            ".url-security-details"
        );

    if (oldDetails) {
        oldDetails.remove();
    }


    // Main container

    const container =
        document.createElement("div");

    container.className =
        "url-security-details";


    // ==================================================
    // TECHNICAL INFORMATION
    // ==================================================

    const technicalCard =
        document.createElement("div");

    technicalCard.className =
        "security-card";

    technicalCard.innerHTML = `

        <h3>
            🔎 Technical URL Information
        </h3>

        <div class="security-grid">

            <div class="security-item">

                <span>
                    Hostname
                </span>

                <strong>
                    ${escapeHTML(
                        details.hostname || "Unknown"
                    )}
                </strong>

            </div>


            <div class="security-item">

                <span>
                    Protocol
                </span>

                <strong>
                    ${escapeHTML(
                        details.protocol || "Unknown"
                    )}
                </strong>

            </div>


            <div class="security-item">

                <span>
                    Resolved IP
                </span>

                <strong>
                    ${
                        resolvedIPs.length
                            ? escapeHTML(
                                resolvedIPs.join(", ")
                              )
                            : "Not available"
                    }
                </strong>

            </div>


            <div class="security-item">

                <span>
                    AI Engine
                </span>

                <strong>
                    🤖 ${escapeHTML(
                        details.aiEngine || "Gemini"
                    )}
                </strong>

            </div>

        </div>

    `;

    container.appendChild(
        technicalCard
    );


    // ==================================================
    // LIVE SERVER CHECK
    // ==================================================

    const liveCard =
        document.createElement("div");

    liveCard.className =
        "security-card";


    const reachable =
        liveCheck.reachable === true;

    const status =
        liveCheck.status || "Unknown";

    const finalURL =
        liveCheck.finalURL || "Unknown";

    const redirects =
        Array.isArray(liveCheck.redirects)
            ? liveCheck.redirects
            : [];


    liveCard.innerHTML = `

        <h3>
            🌐 Live Server Check
        </h3>

        <div class="security-grid">

            <div class="security-item">

                <span>
                    Server Status
                </span>

                <strong>
                    ${
                        reachable
                            ? "🟢 Reachable"
                            : "🔴 Not reachable"
                    }
                </strong>

            </div>


            <div class="security-item">

                <span>
                    HTTP Status
                </span>

                <strong>
                    ${escapeHTML(
                        String(status)
                    )}
                </strong>

            </div>


            <div class="security-item">

                <span>
                    Final URL
                </span>

                <strong>
                    ${escapeHTML(
                        finalURL
                    )}
                </strong>

            </div>


            <div class="security-item">

                <span>
                    Redirects
                </span>

                <strong>
                    ${redirects.length}
                </strong>

            </div>

        </div>

    `;


    // Redirects

    if (redirects.length > 0) {

        const redirectList =
            document.createElement("div");

        redirectList.className =
            "redirect-list";

        redirectList.innerHTML =
            "<h4>↪️ Redirect Chain</h4>";


        redirects.forEach(
            (redirect, index) => {

                const item =
                    document.createElement("div");

                item.className =
                    "redirect-item";

                item.textContent =
                    `${index + 1}. ${redirect}`;

                redirectList.appendChild(
                    item
                );

            }
        );


        liveCard.appendChild(
            redirectList
        );

    }


    container.appendChild(
        liveCard
    );


    // ==================================================
    // SECURITY SIGNALS
    // ==================================================

    const signalsCard =
        document.createElement("div");

    signalsCard.className =
        "security-card";


    signalsCard.innerHTML = `
        <h3>
            ⚠️ Security Signals
        </h3>
    `;


    if (signals.length === 0) {

        const safeMessage =
            document.createElement("div");

        safeMessage.className =
            "signal-safe";

        safeMessage.textContent =
            "✅ No major technical warning signals detected.";

        signalsCard.appendChild(
            safeMessage
        );

    }

    else {

        const signalList =
            document.createElement("div");

        signalList.className =
            "signal-list";


        signals.forEach(
            signal => {

                const item =
                    document.createElement("div");

                item.className =
                    "signal-item";

                item.innerHTML = `

                    <span>
                        ⚠️
                    </span>

                    <span>
                        ${escapeHTML(signal)}
                    </span>

                `;

                signalList.appendChild(
                    item
                );

            }
        );


        signalsCard.appendChild(
            signalList
        );

    }


    container.appendChild(
        signalsCard
    );


    // ==================================================
    // VIRUSTOTAL
    // ==================================================

    if (virusTotal) {

        const vtCard =
            document.createElement("div");

        vtCard.className =
            "security-card";


        if (virusTotal.available) {

            vtCard.innerHTML = `

                <h3>
                    🛡️ Threat Intelligence
                </h3>

                <div class="security-grid">

                    <div class="security-item">

                        <span>
                            Database
                        </span>

                        <strong>
                            VirusTotal
                        </strong>

                    </div>


                    <div class="security-item">

                        <span>
                            Status
                        </span>

                        <strong>
                            ${
                                virusTotal.found
                                    ? "🟢 URL Found"
                                    : "⚪ Not Found"
                            }
                        </strong>

                    </div>


                    <div class="security-item">

                        <span>
                            Malicious
                        </span>

                        <strong>
                            ${
                                virusTotal
                                    .analysisStats
                                    ?.malicious
                                ?? "Unknown"
                            }
                        </strong>

                    </div>


                    <div class="security-item">

                        <span>
                            Suspicious
                        </span>

                        <strong>
                            ${
                                virusTotal
                                    .analysisStats
                                    ?.suspicious
                                ?? "Unknown"
                            }
                        </strong>

                    </div>

                </div>

            `;

        }

        else {

            vtCard.innerHTML = `

                <h3>
                    🛡️ Threat Intelligence
                </h3>

                <div class="security-info">

                    ℹ️ VirusTotal is not configured.

                    ScamGuard is using technical
                    URL inspection and Gemini AI.

                </div>

            `;

        }


        container.appendChild(
            vtCard
        );

    }


    // Add details

    resultBox.appendChild(
        container
    );

}


// ==================================================
// CHECK MESSAGE
// ==================================================

async function checkMessage() {

    const message =
        messageBox.value.trim();


    if (!message) {

        alert(
            "Please paste a message first."
        );

        return;
    }


    checkButton.disabled = true;

    checkButton.textContent =
        "🔍 Checking...";

    showResultBox();


    resultBox.innerHTML = `

        <h2>
            🔍 Analyzing Message...
        </h2>

        <div class="analysis">
            AI is analyzing the message...
        </div>

    `;


    try {

        const response =
            await fetch(
                "/check-message",
                {

                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({
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


        if (Number.isNaN(risk)) {

            throw new Error(
                "Invalid risk value returned by server."
            );

        }


        displayBasicResult(
            risk,
            data.explanation
        );

    }

    catch (error) {

        console.error(
            "❌ Message Analysis Error:",
            error
        );


        resultBox.innerHTML = `

            <h2>
                ❌ Message Analysis Error
            </h2>

            <div class="analysis">

                ${escapeHTML(
                    error.message ||
                    "Unable to analyze message."
                )}

            </div>

        `;

    }

    finally {

        checkButton.disabled = false;

        checkButton.textContent =
            "🔍 Check Message";

    }

}


// ==================================================
// CHECK EMAIL
// ==================================================

async function checkEmail() {

    const sender =
        senderEmail.value.trim();

    const subject =
        emailSubject.value.trim();

    const body =
        emailBody.value.trim();

    const link =
        emailLink.value.trim();


    if (!sender || !subject || !body) {

        alert(
            "Please enter sender email, subject and email content."
        );

        return;
    }


    checkButton.disabled = true;

    checkButton.textContent =
        "📧 Checking Email...";

    showResultBox();


    resultBox.innerHTML = `

        <h2>
            📧 Analyzing Email...
        </h2>

        <div class="analysis">
            AI is analyzing the email...
        </div>

    `;


    try {

        const response =
            await fetch(
                "/check-email",
                {

                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({

                            sender: sender,

                            subject: subject,

                            body: body,

                            link: link

                        })

                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Email analysis failed."
            );

        }


        const risk =
            Number(data.risk);


        if (Number.isNaN(risk)) {

            throw new Error(
                "Invalid risk value returned by server."
            );

        }


        displayBasicResult(
            risk,
            data.explanation
        );

    }

    catch (error) {

        console.error(
            "❌ Email Analysis Error:",
            error
        );


        resultBox.innerHTML = `

            <h2>
                ❌ Email Analysis Error
            </h2>

            <div class="analysis">

                ${escapeHTML(
                    error.message ||
                    "Unable to analyze email."
                )}

            </div>

        `;

    }

    finally {

        checkButton.disabled = false;

        checkButton.textContent =
            "📧 Check Email";

    }

}


// ==================================================
// CHECK URL
// ==================================================

async function checkURL() {

    const url =
        urlInput.value.trim();


    if (!url) {

        alert(
            "Please enter a URL first."
        );

        return;
    }


    // Validate URL

    let parsedURL;

    try {

        parsedURL =
            new URL(url);

    }

    catch {

        alert(
            "Please enter a valid URL.\nExample: https://example.com"
        );

        return;
    }


    // Only HTTP / HTTPS

    if (
        parsedURL.protocol !== "http:" &&
        parsedURL.protocol !== "https:"
    ) {

        alert(
            "Only HTTP and HTTPS URLs are supported."
        );

        return;
    }


    checkButton.disabled = true;

    checkButton.textContent =
        "🔗 Checking URL...";

    showResultBox();


    resultBox.innerHTML = `

        <h2>
            🔍 Scanning URL...
        </h2>

        <div class="scanning">

            Collecting DNS information,
            checking the live server,
            inspecting redirects
            and running Gemini AI analysis...

        </div>

    `;


    try {

        console.log(
            "🔗 Sending URL:",
            url
        );


        const response =
            await fetch(
                "/check-url",
                {

                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({
                            url: url
                        })

                }
            );


        const data =
            await response.json();


        console.log(
            "🔎 URL Server Response:",
            data
        );


        if (!response.ok) {

            throw new Error(
                data.error ||
                data.details ||
                "URL analysis failed."
            );

        }


        const risk =
            Number(data.risk);


        if (Number.isNaN(risk)) {

            throw new Error(
                "Invalid risk value returned by server."
            );

        }


        // ==================================================
        // DISPLAY MAIN RESULT
        // ==================================================

        resultBox.innerHTML = `

            <h2>
                ⚠️ Risk Analysis
            </h2>

            <div class="risk-score-display">

                <span class="risk-number">

                    ${Math.round(risk)}

                </span>

                <span class="risk-out-of">

                    / 100

                </span>

            </div>


            <div class="risk-bar">

                <div
                    class="risk-level"
                    style="width: ${Math.max(
                        0,
                        Math.min(100, risk)
                    )}%"
                ></div>

            </div>


            <div class="analysis">

                ${escapeHTML(
                    data.explanation ||
                    "No explanation received."
                )}

            </div>

        `;


        // Update heading

        const heading =
            resultBox.querySelector("h2");


        if (risk >= 70) {

            heading.textContent =
                `🚨 High Scam Risk: ${Math.round(risk)}%`;

        }

        else if (risk >= 30) {

            heading.textContent =
                `⚠️ Possible Scam: ${Math.round(risk)}%`;

        }

        else {

            heading.textContent =
                `✅ Low Scam Risk: ${Math.round(risk)}%`;

        }


        // ==================================================
        // DISPLAY URL DETAILS
        // ==================================================

        displayURLSecurityDetails(
            data
        );

    }

    catch (error) {

        console.error(
            "❌ URL Analysis Error:",
            error
        );


        resultBox.innerHTML = `

            <h2>
                ❌ URL Analysis Error
            </h2>

            <div class="analysis">

                ${escapeHTML(
                    error.message ||
                    "Unable to analyze the URL."
                )}

            </div>

        `;

    }

    finally {

        checkButton.disabled = false;

        checkButton.textContent =
            "🔗 Check URL";

    }

}


// ==================================================
// CHECK BUTTON
// ==================================================

checkButton.addEventListener(
    "click",
    async function () {

        if (
            urlOption.classList.contains("active")
        ) {

            await checkURL();

            return;
        }


        if (
            emailOption.classList.contains("active")
        ) {

            await checkEmail();

            return;
        }


        await checkMessage();

    }
);


// ==================================================
// CLEAR BUTTON
// ==================================================

clearButton.addEventListener(
    "click",
    function () {

        // Clear message

        messageBox.value = "";


        // Clear email

        senderEmail.value = "";

        emailSubject.value = "";

        emailBody.value = "";

        emailLink.value = "";


        // Clear URL

        urlInput.value = "";


        // Hide result

        resultBox.style.display =
            "none";


        // Clear result

        resultBox.innerHTML = `

            <h2>
                ⚠️ Risk Analysis
            </h2>

        `;


        console.log(
            "🗑️ ScamGuard AI cleared."
        );

    }
);


// ==================================================
// START APPLICATION
// ==================================================

setMessageMode();

console.log(
    "🛡️ ScamGuard AI frontend loaded successfully."
);