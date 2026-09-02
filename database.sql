CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE decks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cards (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    deck_id INTEGER REFERENCES decks(id) ON DELETE CASCADE,
    kanji VARCHAR(50) NOT NULL,
    furigana VARCHAR(100) NOT NULL,
    meaning VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_decks_user_id ON decks(user_id);
CREATE INDEX idx_cards_user_id ON cards(user_id);
CREATE INDEX idx_cards_deck_id ON cards(deck_id);