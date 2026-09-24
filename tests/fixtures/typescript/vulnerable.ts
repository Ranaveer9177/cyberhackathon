import * as https from 'https';

export function runQuery(db: any, userInput: string) {
    const query = `SELECT * FROM items WHERE name = '${userInput}'`;
    return db.query(query);
}

export const insecureAgent = new https.Agent({
    rejectUnauthorized: false
});
