/* ============================================
   Good Code Bad Code — Game Logic
   ============================================ */

// --- Question Data (15 scenarios covering all 12 required categories) ---
const questions = [
  {
    scenario: "SQL Injection Prevention",
    goodCode:
`// Parameterized query
const query = "SELECT * FROM users WHERE id = ?";
db.execute(query, [userId]);`,
    badCode:
`// String concatenation
const query = "SELECT * FROM users WHERE id = " + userId;
db.execute(query);`,
    explanation: "String concatenation in SQL queries allows attackers to inject malicious SQL. Parameterized queries separate code from data, preventing injection attacks."
  },
  {
    scenario: "Cross-Site Scripting (XSS) Prevention",
    goodCode:
`// Safe: uses textContent
const el = document.getElementById("name");
el.textContent = userInput;`,
    badCode:
`// Dangerous: uses innerHTML
const el = document.getElementById("name");
el.innerHTML = userInput;`,
    explanation: "Using innerHTML with user input lets attackers inject malicious scripts. textContent treats input as plain text, preventing XSS attacks."
  },
  {
    scenario: "Password Storage",
    goodCode:
`// Hashed with bcrypt
const hash = await bcrypt.hash(password, 12);
db.save({ email, passwordHash: hash });`,
    badCode:
`// Stored in plain text
db.save({ email, password: password });`,
    explanation: "Storing passwords in plain text means a database breach exposes every user's password. Hashing with bcrypt makes passwords unreadable even if stolen."
  },
  {
    scenario: "Input Validation",
    goodCode:
`// Validate and sanitize
function setAge(input) {
  const age = parseInt(input, 10);
  if (isNaN(age) || age < 0 || age > 150) {
    throw new Error("Invalid age");
  }
  return age;
}`,
    badCode:
`// No validation at all
function setAge(input) {
  return input;
}`,
    explanation: "Unvalidated input can cause crashes, data corruption, or security exploits. Always validate type, range, and format before using input."
  },
  {
    scenario: "Authentication Token Storage",
    goodCode:
`// httpOnly cookie (set by server)
res.cookie("token", jwt, {
  httpOnly: true,
  secure: true,
  sameSite: "Strict"
});`,
    badCode:
`// Stored in localStorage
function login(token) {
  localStorage.setItem("authToken", token);
}`,
    explanation: "localStorage is accessible to any JavaScript on the page, making tokens vulnerable to XSS theft. httpOnly cookies cannot be read by client-side scripts."
  },
  {
    scenario: "Error Handling",
    goodCode:
`// Generic error message
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({
    error: "Something went wrong"
  });
});`,
    badCode:
`// Exposes stack trace to user
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack
  });
});`,
    explanation: "Exposing stack traces reveals internal paths, library versions, and code structure to attackers. Show generic messages to users and log details server-side."
  },
  {
    scenario: "Hardcoded Secrets",
    goodCode:
`// Read from environment
const apiKey = process.env.API_KEY;
fetch(url, {
  headers: { "Authorization": apiKey }
});`,
    badCode:
`// Hardcoded in source code
const apiKey = "sk-a8f3b9c2d4e5f6a7";
fetch(url, {
  headers: { "Authorization": apiKey }
});`,
    explanation: "Hardcoded secrets end up in version control and can be found by anyone with repo access. Environment variables keep secrets out of source code."
  },
  {
    scenario: "HTTPS Usage",
    goodCode:
`// Secure HTTPS endpoint
fetch("https://api.example.com/data")
  .then(res => res.json());`,
    badCode:
`// Insecure HTTP endpoint
fetch("http://api.example.com/data")
  .then(res => res.json());`,
    explanation: "HTTP transmits data in plain text, allowing man-in-the-middle attacks. HTTPS encrypts all traffic between client and server."
  },
  {
    scenario: "Authorization Checks",
    goodCode:
`// Server-side role check
app.delete("/user/:id", (req, res) => {
  const role = getUserRole(req.session.userId);
  if (role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }
  deleteUser(req.params.id);
});`,
    badCode:
`// Trusts client-side role
app.delete("/user/:id", (req, res) => {
  if (req.body.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }
  deleteUser(req.params.id);
});`,
    explanation: "Client-sent data can be forged. Authorization must be verified server-side using session data, not values the client provides in the request body."
  },
  {
    scenario: "File Upload Security",
    goodCode:
`// Validate file type and size
function handleUpload(file) {
  const allowed = ["image/png", "image/jpeg"];
  if (!allowed.includes(file.type)) {
    throw new Error("Invalid file type");
  }
  if (file.size > 5 * 1024 * 1024) {
    throw new Error("File too large");
  }
  saveFile(file);
}`,
    badCode:
`// No validation
function handleUpload(file) {
  saveFile(file);
}`,
    explanation: "Accepting any file allows attackers to upload malicious scripts or executables. Always validate file type, size, and consider scanning content."
  },
  {
    scenario: "Command Injection Prevention",
    goodCode:
`// Safe: use execFile with args array
const { execFile } = require("child_process");
execFile("ping", ["-c", "4", hostname], callback);`,
    badCode:
`// Dangerous: raw input in shell command
const { exec } = require("child_process");
exec("ping -c 4 " + hostname, callback);`,
    explanation: "Concatenating user input into shell commands lets attackers run arbitrary commands (e.g. input: '8.8.8.8; rm -rf /'). execFile avoids shell interpretation."
  },
  {
    scenario: "Logging Sensitive Data",
    goodCode:
`// Mask sensitive fields
function logRequest(req) {
  const safe = { ...req.body };
  if (safe.password) safe.password = "***";
  if (safe.ssn) safe.ssn = "***";
  console.log("Request:", safe);
}`,
    badCode:
`// Logs everything including passwords
function logRequest(req) {
  console.log("Request:", req.body);
}`,
    explanation: "Logging passwords and personal data exposes them in log files, monitoring dashboards, and third-party log services. Always mask sensitive fields."
  },
  {
    scenario: "SQL Injection in Login",
    goodCode:
`// Parameterized login query
const sql = "SELECT * FROM users WHERE email = ? AND pass = ?";
db.query(sql, [email, hashedPass]);`,
    badCode:
`// Concatenated login query
const sql = \`SELECT * FROM users
  WHERE email = '\${email}'
  AND pass = '\${password}'\`;
db.query(sql);`,
    explanation: "An attacker could enter ' OR '1'='1' -- as email to bypass login entirely. Parameterized queries prevent this by escaping all user input."
  },
  {
    scenario: "CSRF Protection",
    goodCode:
`// CSRF token validation
app.post("/transfer", (req, res) => {
  if (req.body.csrfToken !== req.session.csrfToken) {
    return res.status(403).send("Invalid token");
  }
  processTransfer(req.body);
});`,
    badCode:
`// No CSRF protection
app.post("/transfer", (req, res) => {
  processTransfer(req.body);
});`,
    explanation: "Without CSRF tokens, attackers can trick users into submitting requests from malicious sites. CSRF tokens verify that requests originate from your application."
  },
  {
    scenario: "Secure Cookie Configuration",
    goodCode:
`// Secure cookie settings
res.cookie("session", id, {
  httpOnly: true,
  secure: true,
  sameSite: "Strict",
  maxAge: 3600000
});`,
    badCode:
`// Insecure cookie defaults
res.cookie("session", id);`,
    explanation: "Default cookies lack httpOnly (vulnerable to XSS theft), secure (sent over HTTP), and sameSite (vulnerable to CSRF). Always set all security flags."
  }
];

// --- Audio Feedback (Web Audio API) ---
const AudioCtx = window.AudioContext || window.webkitAudioContext;
let audioCtx = null;

function getAudioCtx() {
  if (!audioCtx) {
    try { audioCtx = new AudioCtx(); } catch (e) { /* no audio */ }
  }
  return audioCtx;
}

function playTone(freq, duration, type) {
  const ctx = getAudioCtx();
  if (!ctx) return;
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.type = type || "sine";
  osc.frequency.value = freq;
  gain.gain.value = 0.08;
  gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + duration);
  osc.connect(gain);
  gain.connect(ctx.destination);
  osc.start();
  osc.stop(ctx.currentTime + duration);
}

function playCorrectSound() {
  playTone(523, 0.12, "sine");
  setTimeout(function() { playTone(659, 0.12, "sine"); }, 100);
  setTimeout(function() { playTone(784, 0.2, "sine"); }, 200);
}

function playIncorrectSound() {
  playTone(330, 0.15, "square");
  setTimeout(function() { playTone(277, 0.25, "square"); }, 130);
}

// --- Game State ---
let gameQuestions = [];
let currentIndex = 0;
let score = 0;
let answered = false;
const TOTAL_QUESTIONS = 10;

// --- DOM References ---
const scoreDisplay = document.getElementById("scoreDisplay");
const progressBar = document.getElementById("progressBar");
const questionCount = document.getElementById("questionCount");
const scenario = document.getElementById("scenario");
const cardLeft = document.getElementById("cardLeft");
const cardRight = document.getElementById("cardRight");
const codeLeft = document.getElementById("codeLeft");
const codeRight = document.getElementById("codeRight");
const btnLeft = document.getElementById("btnLeft");
const btnRight = document.getElementById("btnRight");
const feedback = document.getElementById("feedback");
const feedbackIcon = document.getElementById("feedbackIcon");
const feedbackText = document.getElementById("feedbackText");
const explanation = document.getElementById("explanation");
const nextBtn = document.getElementById("nextBtn");
const gameContainer = document.getElementById("gameContainer");
const endScreen = document.getElementById("endScreen");
const endIcon = document.getElementById("endIcon");
const endTitle = document.getElementById("endTitle");
const endScore = document.getElementById("endScore");
const endMessage = document.getElementById("endMessage");
const restartBtn = document.getElementById("restartBtn");

// --- Utilities ---

function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/** Render code with line number spans */
function renderCode(codeEl, codeStr) {
  var lines = codeStr.split('\n');
  codeEl.innerHTML = '';
  lines.forEach(function(line) {
    var span = document.createElement('span');
    span.className = 'line';
    span.textContent = line || ' ';
    codeEl.appendChild(span);
  });
}

// --- Core Game Logic ---

function startGame() {
  gameQuestions = shuffle(questions).slice(0, TOTAL_QUESTIONS).map(function(q) {
    var goodOnLeft = Math.random() < 0.5;
    return {
      scenario: q.scenario,
      goodCode: q.goodCode,
      badCode: q.badCode,
      explanation: q.explanation,
      leftCode: goodOnLeft ? q.goodCode : q.badCode,
      rightCode: goodOnLeft ? q.badCode : q.goodCode,
      correctSide: goodOnLeft ? "left" : "right"
    };
  });

  currentIndex = 0;
  score = 0;
  answered = false;

  endScreen.classList.add("hidden");
  gameContainer.classList.remove("hidden");
  renderQuestion();
}

function renderQuestion() {
  var q = gameQuestions[currentIndex];
  answered = false;

  scoreDisplay.textContent = "Score: " + score + " / " + currentIndex;
  questionCount.textContent = "Question " + (currentIndex + 1) + " of " + TOTAL_QUESTIONS;
  progressBar.style.width = ((currentIndex / TOTAL_QUESTIONS) * 100) + "%";

  scenario.textContent = q.scenario;

  renderCode(codeLeft, q.leftCode);
  renderCode(codeRight, q.rightCode);

  cardLeft.className = "card";
  cardRight.className = "card";
  btnLeft.textContent = "Select";
  btnRight.textContent = "Select";
  feedback.classList.add("hidden");
}

function selectCard(side) {
  if (answered) return;
  answered = true;

  var q = gameQuestions[currentIndex];
  var isCorrect = side === q.correctSide;

  if (isCorrect) {
    score++;
    playCorrectSound();
  } else {
    playIncorrectSound();
  }

  var selectedCard = side === "left" ? cardLeft : cardRight;
  var selectedBtn = side === "left" ? btnLeft : btnRight;

  if (isCorrect) {
    selectedCard.classList.add("correct");
    selectedBtn.textContent = "\u2713 Good Code";
  } else {
    selectedCard.classList.add("incorrect");
    selectedBtn.textContent = "\u2717 Bad Code";
    var correctCard = q.correctSide === "left" ? cardLeft : cardRight;
    var correctBtn = q.correctSide === "left" ? btnLeft : btnRight;
    correctCard.classList.add("reveal-correct");
    correctBtn.textContent = "\u2713 Good Code";
  }

  cardLeft.classList.add("disabled");
  cardRight.classList.add("disabled");

  feedbackIcon.textContent = isCorrect ? "\u2705" : "\u274c";
  feedbackText.textContent = isCorrect ? "Correct!" : "Incorrect!";
  feedbackText.className = "feedback-text " + (isCorrect ? "correct-text" : "incorrect-text");
  explanation.textContent = q.explanation;

  nextBtn.textContent = (currentIndex >= TOTAL_QUESTIONS - 1) ? "See Results" : "Next Question";
  feedback.classList.remove("hidden");

  scoreDisplay.textContent = "Score: " + score + " / " + (currentIndex + 1);
}

function nextQuestion() {
  currentIndex++;
  if (currentIndex >= TOTAL_QUESTIONS) {
    showEndScreen();
  } else {
    renderQuestion();
  }
}

function showEndScreen() {
  gameContainer.classList.add("hidden");
  endScreen.classList.remove("hidden");

  var pct = Math.round((score / TOTAL_QUESTIONS) * 100);
  endScore.textContent = score + " / " + TOTAL_QUESTIONS;

  if (pct === 100) {
    endIcon.textContent = "\uD83C\uDF1F";
    endTitle.textContent = "Perfect Score!";
    endMessage.textContent = "You're a security expert. Every codebase is safer with you on the team.";
  } else if (pct >= 80) {
    endIcon.textContent = "\uD83C\uDF89";
    endTitle.textContent = "Great Job!";
    endMessage.textContent = "You have a strong eye for secure code. Keep it up!";
  } else if (pct >= 60) {
    endIcon.textContent = "\uD83D\uDC4D";
    endTitle.textContent = "Not Bad!";
    endMessage.textContent = "You're getting there. Review the explanations to strengthen your knowledge.";
  } else {
    endIcon.textContent = "\uD83D\uDCDA";
    endTitle.textContent = "Keep Learning!";
    endMessage.textContent = "Security takes practice. Try again and read the explanations carefully.";
  }

  progressBar.style.width = "100%";
}

// --- Event Listeners ---
btnLeft.addEventListener("click", function() { selectCard("left"); });
btnRight.addEventListener("click", function() { selectCard("right"); });
nextBtn.addEventListener("click", nextQuestion);
restartBtn.addEventListener("click", startGame);

// --- Start ---
startGame();
