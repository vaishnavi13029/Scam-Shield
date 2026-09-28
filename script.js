 // ==========================================
// SCAMSHIELD - SCAM MESSAGE ANALYZER
// ==========================================


// ------------------------------------------
// DOM ELEMENTS
// ------------------------------------------

const messageInput = document.getElementById("messageInput");

const analyzeBtn = document.getElementById("analyzeBtn");

const clearBtn = document.getElementById("clearBtn");

const results = document.getElementById("results");

const riskScore = document.getElementById("riskScore");

const riskLevel = document.getElementById("riskLevel");

const riskBar = document.getElementById("riskBar");

const summary = document.getElementById("summary");

const warningList = document.getElementById("warningList");

const safetyList = document.getElementById("safetyList");


// ------------------------------------------
// SCAM DETECTION PATTERNS
// ------------------------------------------

const patterns = [

    {
        name: "Urgency / Threat",
        score: 20,

        keywords: [
            // English
            "urgent",
            "urgently",
            "immediately",
            "act now",
            "action required",
            "respond now",
            "within 24 hours",
            "within 48 hours",
            "today",
            "right now",
            "last warning",
            "final warning",
            "account will be blocked",
            "account will be suspended",
            "account will be deactivated",
            "account will be closed",
            "expires today",
            "do it now",
            "verify immediately",
            "legal action",
            "avoid penalty",

            // Hindi
            "तुरंत",
            "अभी करें",
            "जल्दी करें",
            "आज ही",
            "अंतिम चेतावनी",
            "खाता बंद",
            "खाता बंद हो जाएगा",
            "खाता निलंबित",
            "खाता निलंबित हो जाएगा",
            "खाता बंद कर दिया जाएगा",
            "24 घंटे के अंदर",
            "कानूनी कार्रवाई",
            "जुर्माना",
            "सत्यापन तुरंत करें",

            // Hinglish
            "turant",
            "abhi karo",
            "jaldi karo",
            "aaj hi",
            "last warning",
            "account band",
            "account band ho jayega",
            "account suspend",
            "account deactivate",
            "account close",
            "24 ghante ke andar",
            "legal action",
            "penalty",
            "turant verify karo"
        ],

        explanation:
            "The message creates pressure or threatens consequences to make you act quickly."
    },


    {
        name: "OTP / Password Request",
        score: 25,

        keywords: [
            // English
            "otp",
            "one time password",
            "one-time password",
            "verification code",
            "security code",
            "password",
            "passcode",
            "login details",
            "login credentials",
            "pin",
            "upi pin",
            "atm pin",
            "cvv",
            "six digit code",
            "6 digit code",
            "share your otp",
            "send your otp",
            "provide your otp",
            "share the code",
            "send the code",

            // Hindi
            "ओटीपी",
            "वन टाइम पासवर्ड",
            "वेरिफिकेशन कोड",
            "सत्यापन कोड",
            "सुरक्षा कोड",
            "पासवर्ड",
            "पिन",
            "यूपीआई पिन",
            "सीवीवी",
            "ओटीपी साझा करें",
            "ओटीपी भेजें",
            "कोड साझा करें",

            // Hinglish
            "otp share karo",
            "otp bhejo",
            "otp batao",
            "otp send karo",
            "verification code share karo",
            "code share karo",
            "password share karo",
            "pin batao",
            "upi pin share karo"
        ],

        explanation:
            "The message asks for sensitive authentication information such as an OTP, password, PIN or security code."
    },


    {
        name: "Suspicious Link",
        score: 30,

        keywords: [
            // English
            "http://",
            "https://",
            "www.",
            "bit.ly",
            "tinyurl",
            "t.co/",
            "click here",
            "click the link",
            "click this link",
            "open this link",
            "tap here",
            "verify here",
            "verify using this link",
            "login here",
            "update here",
            "download here",
            "link below",

            // Hindi
            "इस लिंक पर क्लिक करें",
            "लिंक पर क्लिक करें",
            "यहां क्लिक करें",
            "इस लिंक को खोलें",
            "लिंक खोलें",
            "लिंक से सत्यापित करें",
            "लिंक पर जाएं",

            // Hinglish
            "link par click karo",
            "link par click karein",
            "is link par click karo",
            "link kholo",
            "link open karo",
            "yahan click karo",
            "link se verify karo",
            "link par jao"
        ],

        explanation:
            "The message contains a link or encourages the user to open a potentially suspicious link."
    },


    {
        name: "Financial Request",
        score: 20,

        keywords: [
            // English
            "pay",
            "payment",
            "make a payment",
            "send money",
            "transfer money",
            "upi",
            "upi payment",
            "upi id",
            "payment request",
            "processing fee",
            "registration fee",
            "service fee",
            "verification fee",
            "security deposit",
            "advance payment",
            "bank account",
            "account number",
            "credit card",
            "debit card",
            "₹",
            "rs.",
            "inr",
            "money transfer",
            "transaction",
            "refund fee",

            // Hindi
            "पैसे भेजें",
            "पैसे ट्रांसफर करें",
            "भुगतान करें",
            "यूपीआई",
            "यूपीआई से भुगतान",
            "यूपीआई आईडी",
            "बैंक खाता",
            "खाता नंबर",
            "पंजीकरण शुल्क",
            "प्रोसेसिंग शुल्क",
            "सत्यापन शुल्क",
            "सुरक्षा जमा",
            "पैसे जमा करें",
            "रिफंड शुल्क",

            // Hinglish
            "paise bhejo",
            "paise bhej do",
            "paise transfer karo",
            "payment karo",
            "upi se payment karo",
            "upi id bhejo",
            "bank account do",
            "account number do",
            "registration fee do",
            "processing fee do",
            "verification fee do",
            "paise jama karo",
            "refund fee do"
        ],

        explanation:
            "The message involves money, payment, banking or financial information."
    },


    {
        name: "Prize / Reward",
        score: 15,

        keywords: [
            // English
            "you won",
            "you have won",
            "winner",
            "lucky winner",
            "congratulations",
            "prize",
            "reward",
            "lottery",
            "cash prize",
            "cash reward",
            "free gift",
            "gift voucher",
            "gift card",
            "lucky draw",
            "jackpot",
            "bonus",
            "claim your",
            "claim reward",
            "claim prize",
            "free money",

            // Hindi
            "आप जीत गए",
            "आप जीत चुके हैं",
            "विजेता",
            "भाग्यशाली विजेता",
            "बधाई हो",
            "इनाम",
            "पुरस्कार",
            "लॉटरी",
            "नकद पुरस्कार",
            "मुफ्त उपहार",
            "उपहार वाउचर",
            "लकी ड्रा",
            "जैकपॉट",
            "अपना इनाम प्राप्त करें",

            // Hinglish
            "aap jeet gaye",
            "aap winner ho",
            "badhai ho",
            "inaam",
            "puraskar",
            "lottery jeeti",
            "cash prize",
            "free gift",
            "lucky winner",
            "prize claim karo",
            "reward claim karo"
        ],

        explanation:
            "The message uses a prize, reward or unexpected benefit to attract the recipient."
    },


    {
        name: "Impersonation",
        score: 15,

        keywords: [
            // English
            "bank official",
            "bank officer",
            "bank representative",
            "customer care",
            "customer support",
            "government",
            "government official",
            "income tax",
            "police",
            "cyber crime",
            "cybercrime",
            "customs",
            "courier",
            "rbi",
            "reserve bank",
            "sbi",
            "hdfc",
            "icici",
            "axis bank",
            "paytm",
            "phonepe",
            "google pay",
            "gpay",
            "amazon",
            "flipkart",
            "uidai",
            "aadhaar",
            "pan card",

            // Hindi
            "बैंक अधिकारी",
            "बैंक कर्मचारी",
            "सरकारी अधिकारी",
            "आयकर विभाग",
            "पुलिस",
            "साइबर क्राइम",
            "सीमा शुल्क",
            "आरबीआई",
            "एसबीआई",
            "आधार",
            "पैन कार्ड",

            // Hinglish
            "bank officer",
            "bank wale",
            "bank employee",
            "government officer",
            "police officer",
            "cyber crime department",
            "income tax department",
            "rbi officer",
            "sbi officer"
        ],

        explanation:
            "The message may be presenting itself as a bank, company, government authority or other trusted organization."
    },


    {
        name: "Delivery / Courier Scam",
        score: 20,

        keywords: [
            "parcel",
            "package",
            "courier",
            "delivery",
            "delivery failed",
            "package held",
            "parcel held",
            "shipment",
            "shipment on hold",
            "customs fee",
            "delivery fee",
            "update delivery address",
            "confirm your address",
            "pay delivery fee",

            // Hindi
            "पार्सल",
            "पैकेज",
            "कूरियर",
            "डिलीवरी",
            "पार्सल रुका हुआ",
            "पार्सल रोक दिया गया",
            "डिलीवरी शुल्क",
            "पता अपडेट करें",
            "अपना पता सत्यापित करें",

            // Hinglish
            "parcel ruk gaya",
            "parcel hold par hai",
            "delivery ruk gayi",
            "address update karo",
            "address verify karo",
            "delivery fee do",
            "courier charge do"
        ],

        explanation:
            "The message uses a delivery or parcel problem to pressure the recipient into paying money or providing information."
    },


    {
        name: "Fake Job / Employment Scam",
        score: 20,

        keywords: [
            "work from home",
            "work-from-home",
            "part time job",
            "part-time job",
            "easy job",
            "online job",
            "job opportunity",
            "job offer",
            "hiring now",
            "immediate joining",
            "earn money",
            "daily income",
            "guaranteed income",
            "no experience required",
            "no experience needed",
            "job registration",
            "training fee",

            // Hindi
            "घर बैठे काम",
            "घर बैठे पैसे कमाएं",
            "नौकरी का मौका",
            "नौकरी का ऑफर",
            "बिना अनुभव नौकरी",
            "रोज कमाएं",
            "गारंटीड कमाई",
            "तुरंत जॉइनिंग",
            "नौकरी पंजीकरण",

            // Hinglish
            "ghar baithe kaam",
            "ghar baithe paise kamao",
            "job ka mauka",
            "job offer",
            "bina experience job",
            "daily income",
            "guaranteed income",
            "turant joining",
            "job registration fee"
        ],

        explanation:
            "The message presents an unexpected job or income opportunity, sometimes combined with fees or unrealistic earnings."
    },


    {
        name: "SIM / Mobile Scam",
        score: 20,

        keywords: [
            "sim will be blocked",
            "sim will be deactivated",
            "sim card will be blocked",
            "mobile number will be blocked",
            "number will be deactivated",
            "kyc update required",
            "sim kyc",
            "mobile kyc",
            "reactivate your sim",
            "verify your mobile number",

            // Hindi
            "सिम बंद हो जाएगा",
            "सिम बंद कर दिया जाएगा",
            "सिम निष्क्रिय",
            "मोबाइल नंबर बंद",
            "मोबाइल नंबर निलंबित",
            "केवाईसी अपडेट करें",
            "सिम केवाईसी",
            "मोबाइल केवाईसी",

            // Hinglish
            "sim band ho jayega",
            "sim deactivate ho jayega",
            "number band ho jayega",
            "mobile number band",
            "kyc update karo",
            "sim kyc karo",
            "mobile kyc update karo"
        ],

        explanation:
            "The message threatens SIM or mobile-service disruption and may attempt to obtain personal information or payment."
    },


    {
        name: "Government / Police Threat",
        score: 25,

        keywords: [
            "police case",
            "police complaint",
            "fir registered",
            "arrest warrant",
            "warrant issued",
            "legal notice",
            "court notice",
            "court case",
            "income tax notice",
            "tax penalty",
            "government notice",
            "cyber crime department",
            "criminal case",
            "arrest",
            "penalty will be imposed",

            // Hindi
            "पुलिस केस",
            "पुलिस शिकायत",
            "एफआईआर दर्ज",
            "गिरफ्तारी वारंट",
            "वारंट जारी",
            "कानूनी नोटिस",
            "अदालत का नोटिस",
            "आयकर नोटिस",
            "टैक्स जुर्माना",
            "सरकारी नोटिस",
            "साइबर अपराध विभाग",
            "आपराधिक मामला",
            "गिरफ्तार",

            // Hinglish
            "police case hai",
            "police complaint",
            "fir darj hai",
            "arrest warrant",
            "warrant issue",
            "legal notice",
            "court notice",
            "income tax notice",
            "tax penalty",
            "government notice",
            "cyber crime case"
        ],

        explanation:
            "The message uses fear of police, legal or government action to pressure the recipient into responding or making a payment."
    },


    {
        name: "Investment / Trading Scam",
        score: 20,

        keywords: [
            "guaranteed returns",
            "guaranteed profit",
            "double your money",
            "triple your money",
            "risk free investment",
            "risk-free investment",
            "quick profit",
            "easy profit",
            "huge returns",
            "high returns",
            "instant profit",
            "investment opportunity",
            "stock tips",
            "trading tips",
            "crypto investment",
            "bitcoin investment",
            "forex investment",
            "minimum investment",
            "profit guaranteed",

            // Hindi
            "गारंटीड रिटर्न",
            "गारंटीड मुनाफा",
            "पैसे दोगुने",
            "पैसे तीन गुना",
            "बिना जोखिम निवेश",
            "जल्दी मुनाफा",
            "आसान मुनाफा",
            "ज्यादा रिटर्न",
            "निवेश का मौका",
            "शेयर टिप्स",
            "क्रिप्टो निवेश",

            // Hinglish
            "guaranteed return",
            "guaranteed profit",
            "paise double",
            "paise triple",
            "risk free investment",
            "jaldi profit",
            "easy profit",
            "high return",
            "investment ka mauka",
            "stock tips",
            "crypto investment"
        ],

        explanation:
            "The message promotes unusually attractive investment or trading returns and may pressure the recipient to send money."
    }

];


// ------------------------------------------
// ANALYZE FUNCTION
// ------------------------------------------

function analyzeMessage() {

    const message = messageInput.value.trim().toLowerCase();


    // Check empty input

    if (message === "") {

        alert("Please paste a message first.");

        return;
    }


    let totalScore = 0;

    let detectedWarnings = [];


    // --------------------------------------
    // CHECK EVERY PATTERN
    // --------------------------------------

    patterns.forEach(pattern => {

        let foundKeyword = null;


        for (let keyword of pattern.keywords) {

            if (message.includes(keyword.toLowerCase())) {

                foundKeyword = keyword;

                break;
            }
        }


        if (foundKeyword) {

            totalScore += pattern.score;


            detectedWarnings.push({

                name: pattern.name,

                score: pattern.score,

                keyword: foundKeyword,

                explanation: pattern.explanation

            });

        }

    });


    // --------------------------------------
    // EXTRA CHECK: MANY EXCLAMATION MARKS
    // --------------------------------------

    const exclamationCount =
        (message.match(/!/g) || []).length;


    if (exclamationCount >= 3) {

        totalScore += 5;

        detectedWarnings.push({

            name: "Aggressive / Attention-Grabbing Language",

            score: 5,

            keyword: "!",

            explanation:
                "Repeated punctuation may be used to create urgency or grab attention."

        });

    }


    // --------------------------------------
    // CAP SCORE AT 100
    // --------------------------------------

    totalScore = Math.min(totalScore, 100);


    // --------------------------------------
    // DETERMINE RISK LEVEL
    // --------------------------------------

    let level;

    if (totalScore >= 60) {

        level = "HIGH RISK";

    }

    else if (totalScore >= 30) {

        level = "MEDIUM RISK";

    }

    else {

        level = "LOW RISK";

    }


    // --------------------------------------
    // DISPLAY RESULT
    // --------------------------------------

    displayResults(
        totalScore,
        level,
        detectedWarnings
    );

}


// ------------------------------------------
// DISPLAY RESULTS
// ------------------------------------------

function displayResults(score, level, warnings) {

    results.classList.remove("hidden");


    // Score

    riskScore.textContent = score;

    riskLevel.textContent = level;


    // --------------------------------------
    // COLOR / BAR
    // --------------------------------------

    riskBar.style.width = score + "%";


    if (score >= 60) {

        riskLevel.style.color = "#d92d20";

        riskBar.style.background = "#d92d20";

        document.querySelector(".score-circle").style.borderColor = "#d92d20";
document.querySelector(".score-circle").style.color = "#d92d20"; 

        summary.textContent =
            "This message contains multiple characteristics commonly associated with scam messages. Avoid clicking links or sharing sensitive information until you independently verify the sender.";

    }

    else if (score >= 30) {

        riskLevel.style.color = "#dc6803";

        riskBar.style.background = "#dc6803";

        document.querySelector(".score-circle").style.borderColor = "#dc6803";
document.querySelector(".score-circle").style.color = "#dc6803";

        summary.textContent =
            "This message contains some warning signs. Be cautious and independently verify the sender before taking any action.";

    }

    else {

        riskLevel.style.color = "#039855";

        riskBar.style.background = "#039855";

        document.querySelector(".score-circle").style.borderColor = "#039855";
document.querySelector(".score-circle").style.color = "#039855";

        summary.textContent =
            "Few common scam indicators were detected. However, automated analysis cannot guarantee that a message is safe.";

    }


    // --------------------------------------
    // WARNING LIST
    // --------------------------------------

    // --------------------------------------
// WARNING LIST
// --------------------------------------

warningList.innerHTML = "";


if (warnings.length === 0) {

    warningList.innerHTML = `

        <div class="warning-item safe-warning">

            <strong>✅ No major warning signs detected</strong>

            <span>
                ScamShield did not detect any of its predefined
                scam indicators in this message.
            </span>

        </div>

    `;

}

else {

    warnings.forEach(warning => {

        const item = document.createElement("div");

        item.className = "warning-item";


        item.innerHTML = `

            <div class="warning-header">

                <strong>⚠️ ${warning.name}</strong>

                <span class="warning-points">
                    +${warning.score}
                </span>

            </div>

            <span class="detected-text">
                Detected phrase:
                <b>"${escapeHTML(warning.keyword)}"</b>
            </span>

            <p>
                ${warning.explanation}
            </p>

        `;


        warningList.appendChild(item);

    });

}


    // --------------------------------------
    // SAFETY ADVICE
    // --------------------------------------

    // --------------------------------------
// DYNAMIC SAFETY ADVICE
// --------------------------------------

safetyList.innerHTML = "";


// Always give this advice
addSafetyTip(
    "🔎",
    "Verify the sender independently before taking action."
);


// OTP / password detected
if (warnings.some(w => w.name === "OTP / Password Request")) {

    addSafetyTip(
        "🔐",
        "Never share OTPs, passwords, PINs or CVV numbers."
    );

}


// Suspicious link detected
if (warnings.some(w => w.name === "Suspicious Link")) {

    addSafetyTip(
        "🔗",
        "Avoid clicking suspicious links. Open the organization's official website or app manually."
    );

}


// Financial request detected
if (warnings.some(w => w.name === "Financial Request")) {

    addSafetyTip(
        "💳",
        "Verify unexpected payment or money requests through an independent channel."
    );

}


// Prize detected
if (warnings.some(w => w.name === "Prize / Reward")) {

    addSafetyTip(
        "🎁",
        "Be cautious of unexpected prizes or rewards that require payment or personal information."
    );

}


// Urgency detected
if (warnings.some(w => w.name === "Urgency / Threat")) {

    addSafetyTip(
        "⏱️",
        "Don't let urgency pressure you into making a quick decision."
    );

}


// Helper function
function addSafetyTip(icon, message) {

    const li = document.createElement("li");

    li.innerHTML = `${icon} ${message}`;

    safetyList.appendChild(li);

}


    // --------------------------------------
    // SCROLL TO RESULT
    // --------------------------------------

    results.scrollIntoView({

        behavior: "smooth",

        block: "start"

    });

}


// ------------------------------------------
// CLEAR BUTTON
// ------------------------------------------

clearBtn.addEventListener("click", () => {

    messageInput.value = "";

    results.classList.add("hidden");

});


// ------------------------------------------
// ANALYZE BUTTON
// ------------------------------------------

analyzeBtn.addEventListener("click", analyzeMessage);


// ------------------------------------------
// CTRL + ENTER
// ------------------------------------------

messageInput.addEventListener("keydown", function(event) {

    if (event.ctrlKey && event.key === "Enter") {

        analyzeMessage();

    }

});


// ------------------------------------------
// EXAMPLE MESSAGES
// ------------------------------------------

function loadExample(type) {

    if (type === "bank") {

        messageInput.value =
            "URGENT! Your bank account will be blocked today. Click here to verify your account and enter your OTP immediately!";

    }


    else if (type === "prize") {

        messageInput.value =
            "Congratulations! You are the lucky winner of a ₹50,000 cash prize. Claim your reward immediately by clicking this link and paying a small processing fee.";

    }


    else if (type === "normal") {

        messageInput.value =
            "Hey! Are we meeting at college at 4 PM today? I have the notes from today's lecture.";

    }

}


// ------------------------------------------
// BASIC HTML ESCAPING
// ------------------------------------------

function escapeHTML(text) {

    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}