const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const KANJI_PER_WEEK = 10;

// Konfigurasi koneksi NeonDB
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ==========================================
// SISTEM IN-MEMORY CACHE & INVALIDATION
// ==========================================
const appCache = new Map();

const clearUserCache = (userId) => {
  appCache.delete(`decks_${userId}`);
  appCache.delete(`cards_${userId}`);
  appCache.delete('public_game_data'); 
};

// ==========================================
// MIDDLEWARE AUTHENTICATION
// ==========================================
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Akses ditolak." });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) { res.status(403).json({ message: "Token tidak valid." }); }
};

const requireAuthView = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');
  try {
    jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    res.clearCookie("token");
    res.redirect('/login');
  }
};

// =====================================
// AUTH ROUTES
// =====================================
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    if (user.rows.length === 0) return res.status(400).json({ message: "Username/password salah." });

    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) return res.status(400).json({ message: "Username/password salah." });

    const token = jwt.sign({ id: user.rows[0].id, username: user.rows[0].username }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.cookie("token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production", maxAge: 604800000 });
    res.json({ message: "Login berhasil!" });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post("/api/auth/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const exists = await pool.query("SELECT id FROM users WHERE username = $1", [username]);
    if (exists.rows.length > 0) return res.status(400).json({ message: "Username digunakan." });
    
    const hashed = await bcrypt.hash(password, await bcrypt.genSalt(10));
    await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [username, hashed]);
    res.status(201).json({ message: "Registrasi berhasil." });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logout berhasil" });
});

// =====================================
// API DECKS (ADMIN AREA)
// =====================================
app.get("/api/decks", authenticateToken, async (req, res) => {
  try {
    const cacheKey = `decks_${req.user.id}`;
    if (appCache.has(cacheKey)) return res.json(appCache.get(cacheKey));

    const result = await pool.query("SELECT * FROM decks WHERE user_id = $1 ORDER BY created_at DESC", [req.user.id]);
    appCache.set(cacheKey, result.rows);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/decks", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("INSERT INTO decks (user_id, name) VALUES ($1, $2) RETURNING *", [req.user.id, req.body.name]);
    clearUserCache(req.user.id); 
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put("/api/decks/:id", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("UPDATE decks SET name = $1 WHERE id = $2 AND user_id = $3 RETURNING *", [req.body.name, req.params.id, req.user.id]);
    clearUserCache(req.user.id);
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete("/api/decks/:id", authenticateToken, async (req, res) => {
  try {
    await pool.query("DELETE FROM decks WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);
    clearUserCache(req.user.id);
    res.json({ message: "Terhapus" });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =====================================
// API CARDS (ADMIN AREA)
// =====================================
app.get("/api/cards", authenticateToken, async (req, res) => {
  try {
    const cacheKey = `cards_${req.user.id}`;
    if (appCache.has(cacheKey)) return res.json(appCache.get(cacheKey));

    const result = await pool.query(`
      SELECT cards.*, decks.name as deck_name 
      FROM cards 
      LEFT JOIN decks ON cards.deck_id = decks.id 
      WHERE cards.user_id = $1 
      ORDER BY cards.created_at DESC
    `, [req.user.id]);
    
    appCache.set(cacheKey, result.rows);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/cards", authenticateToken, async (req, res) => {
  const { deck_id, kanji, furigana, meaning } = req.body;
  try {
    const result = await pool.query(
      "INSERT INTO cards (user_id, deck_id, kanji, furigana, meaning) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [req.user.id, deck_id, kanji, furigana, meaning]
    );
    clearUserCache(req.user.id); 
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put("/api/cards/:id", authenticateToken, async (req, res) => {
  const { deck_id, kanji, furigana, meaning } = req.body;
  try {
    const result = await pool.query(
      "UPDATE cards SET deck_id = $1, kanji = $2, furigana = $3, meaning = $4 WHERE id = $5 AND user_id = $6 RETURNING *",
      [deck_id, kanji, furigana, meaning, req.params.id, req.user.id]
    );
    clearUserCache(req.user.id); 
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete("/api/cards/:id", authenticateToken, async (req, res) => {
  try {
    await pool.query("DELETE FROM cards WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);
    clearUserCache(req.user.id); 
    res.json({ message: "Terhapus" });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =====================================
// API KANJI & QUIZ (PUBLIC GAMEPLAY)
// =====================================
app.get("/api/kanji/week/:weekNumber", async (req, res) => {
  try {
    const cacheKey = 'public_game_data';
    let allKanji;

    if (appCache.has(cacheKey)) {
      allKanji = appCache.get(cacheKey);
    } else {
      const result = await pool.query("SELECT * FROM cards ORDER BY id ASC");
      allKanji = result.rows;
      appCache.set(cacheKey, allKanji);
    }

    const week = parseInt(req.params.weekNumber, 10);
    const startIndex = (week - 1) * KANJI_PER_WEEK;
    const weeklyKanji = allKanji.slice(startIndex, startIndex + KANJI_PER_WEEK);

    if (weeklyKanji.length === 0) return res.status(404).json({ message: "Belum ada kartu." });
    res.json({ totalWeeks: Math.ceil(allKanji.length / KANJI_PER_WEEK), totalKanji: allKanji.length, kanjiData: weeklyKanji });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/quiz/week/:weekNumber", async (req, res) => {
  try {
    const cacheKey = 'public_game_data';
    let allKanji;

    if (appCache.has(cacheKey)) {
      allKanji = appCache.get(cacheKey);
    } else {
      const result = await pool.query("SELECT * FROM cards ORDER BY id ASC");
      allKanji = result.rows;
      appCache.set(cacheKey, allKanji);
    }

    const week = parseInt(req.params.weekNumber, 10);
    const weeklyKanji = allKanji.slice((week - 1) * KANJI_PER_WEEK, ((week - 1) * KANJI_PER_WEEK) + KANJI_PER_WEEK);

    if (weeklyKanji.length === 0) return res.status(404).json({ message: "Tidak ada kartu." });

    // Acak urutan kartu agar jenis soal jatuh ke kanji yang acak juga
    const shuffledWeekly = [...weeklyKanji].sort(() => Math.random() - 0.5);

    // Iterasi membagi merata 4 tipe kuis menggunakan modulo
    const quizData = shuffledWeekly.map((card, index) => {
      const questionType = index % 4;
      let prompt, subject, answer, typeKeyForOptions;

      if (questionType === 0) {
        prompt = "Bagaimana cara membaca Kanji ini?";
        subject = card.kanji;
        answer = card.furigana;
        typeKeyForOptions = 'furigana';
      } else if (questionType === 1) {
        prompt = "Apa arti dari Kanji ini?";
        subject = card.kanji;
        answer = card.meaning;
        typeKeyForOptions = 'meaning';
      } else if (questionType === 2) {
        prompt = "Pilih Kanji yang sesuai dengan cara baca ini:";
        subject = card.furigana;
        answer = card.kanji;
        typeKeyForOptions = 'kanji';
      } else {
        prompt = "Pilih Kanji yang memiliki arti ini:";
        subject = card.meaning;
        answer = card.kanji;
        typeKeyForOptions = 'kanji';
      }

      const wrongOptions = new Set();
      // Filter opsi yang benar dari kolam jawaban
      const poolChoices = allKanji.filter(k => k[typeKeyForOptions] !== card[typeKeyForOptions]);
      
      while(wrongOptions.size < 3 && poolChoices.length > 0) {
        const randomIndex = Math.floor(Math.random() * poolChoices.length);
        wrongOptions.add(poolChoices.splice(randomIndex, 1)[0][typeKeyForOptions]);
      }
      
      return {
        prompt: prompt,
        subject: subject,
        answer: answer,
        options: [...Array.from(wrongOptions), answer].sort(() => Math.random() - 0.5)
      };
    });

    // Acak ulang susunan soal yang sudah di-generate sebelum dikirim ke user
    res.json(quizData.sort(() => Math.random() - 0.5));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =====================================
// VIEWS ROUTES
// =====================================
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/study-mode", (req, res) => res.sendFile(path.join(__dirname, "public", "study-mode.html")));
app.get("/history", (req, res) => res.sendFile(path.join(__dirname, "public", "history.html")));
app.get("/quiz", (req, res) => res.sendFile(path.join(__dirname, "public", "quiz.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/admin", requireAuthView, (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));
app.get("/import", requireAuthView, (req, res) => res.sendFile(path.join(__dirname, "public", "import.html")));

app.listen(PORT, () => console.log(`🚀 Server jalan di port ${PORT}`));