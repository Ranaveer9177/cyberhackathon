import * as https from 'https';

export function runQuery(db: any, userInput: string) {
    return db.query('SELECT * FROM items WHERE name = ?', [userInput]);
}

export const secureAgent = new https.Agent({
    rejectUnauthorized: true
});
